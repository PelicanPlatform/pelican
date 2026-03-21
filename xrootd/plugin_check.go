/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package xrootd

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

var (
	pluginSearchPathsOnce sync.Once
	pluginSearchPaths     []string
)

// resetPluginSearchPathsForTesting resets the cached plugin search paths.
// This should only be used in tests.
func resetPluginSearchPathsForTesting() {
	pluginSearchPathsOnce = sync.Once{}
	pluginSearchPaths = nil
}

// deduplicatePaths resolves paths to absolute paths and removes duplicates while preserving order.
func deduplicatePaths(paths []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, path := range paths {
		// Resolve to absolute path
		absPath, err := filepath.Abs(path)
		if err != nil {
			// If we can't resolve, use the original path
			absPath = path
		}
		// Clean the path to normalize it
		absPath = filepath.Clean(absPath)
		// Add if not seen before
		if !seen[absPath] {
			seen[absPath] = true
			result = append(result, absPath)
		}
	}
	return result
}

// getPluginSearchPaths returns a list of directories to search for XRootD plugins.
// It includes standard library paths and paths from environment variables.
func getPluginSearchPaths() []string {
	pluginSearchPathsOnce.Do(func() {
		searchPaths := []string{}

		// Add standard library paths based on platform
		switch runtime.GOOS {
		case "darwin":
			searchPaths = append(searchPaths,
				"/usr/local/lib",
				"/opt/homebrew/lib",
				"/usr/lib",
			)
		case "linux":
			searchPaths = append(searchPaths,
				"/usr/lib",
				"/usr/lib64",
				"/usr/local/lib",
				"/usr/local/lib64",
			)
		default:
			// For other platforms, use basic paths
			searchPaths = append(searchPaths,
				"/usr/lib",
				"/usr/local/lib",
			)
		}

		// Append paths from environment variables
		appendEnvPaths := func(envVar string) {
			if path := os.Getenv(envVar); path != "" {
				for _, p := range strings.Split(path, string(os.PathListSeparator)) {
					if p != "" {
						searchPaths = append(searchPaths, p)
					}
				}
			}
		}

		appendEnvPaths("LD_LIBRARY_PATH")
		appendEnvPaths("DYLD_LIBRARY_PATH")
		appendEnvPaths("DYLD_FALLBACK_LIBRARY_PATH")

		// On Linux, parse /etc/ld.so.conf to get additional system paths
		if runtime.GOOS == "linux" {
			searchPaths = append(searchPaths, parseLdSoConf()...)
		}

		// Add XRootD's RPATH (../lib and ../lib64 relative to xrootd binary)
		searchPaths = append(searchPaths, getXRootDRPaths()...)

		// Resolve absolute paths and remove duplicates while preserving order
		pluginSearchPaths = deduplicatePaths(searchPaths)
	})

	return pluginSearchPaths
}

// parseLdSoConf parses /etc/ld.so.conf and included files to get library paths
func parseLdSoConf() []string {
	paths := []string{}
	seenFiles := make(map[string]bool)
	seenPaths := make(map[string]bool)

	var parseFile func(string)
	parseFile = func(filename string) {
		// Check if we've already parsed this file to avoid include loops
		if seenFiles[filename] {
			return
		}
		seenFiles[filename] = true

		file, err := os.Open(filename)
		if err != nil {
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Handle include directive
			if strings.HasPrefix(line, "include ") {
				pattern := strings.TrimSpace(strings.TrimPrefix(line, "include"))
				// Expand glob pattern
				matches, err := filepath.Glob(pattern)
				if err == nil {
					for _, match := range matches {
						parseFile(match)
					}
				}
			} else {
				// It's a library path
				if !seenPaths[line] && filepath.IsAbs(line) {
					seenPaths[line] = true
					paths = append(paths, line)
				}
			}
		}
	}

	parseFile("/etc/ld.so.conf")
	return paths
}

// getXRootDRPaths returns paths relative to the xrootd binary (../lib and ../lib64)
func getXRootDRPaths() []string {
	paths := []string{}

	// Find xrootd binary location
	xrootdPath, err := exec.LookPath("xrootd")
	if err != nil {
		return paths
	}

	// Resolve to absolute path
	xrootdPath, err = filepath.Abs(xrootdPath)
	if err != nil {
		return paths
	}

	// Get the directory containing xrootd binary
	binDir := filepath.Dir(xrootdPath)

	// Add ../lib and ../lib64 relative to bin directory
	libDir := filepath.Join(binDir, "..", "lib")
	lib64Dir := filepath.Join(binDir, "..", "lib64")

	if _, err := os.Stat(libDir); err == nil {
		paths = append(paths, libDir)
	}
	if _, err := os.Stat(lib64Dir); err == nil {
		paths = append(paths, lib64Dir)
	}

	return paths
}

// getClientPluginPaths parses XRootD client plugin configuration files and returns
// directories containing absolute library paths from enabled plugins.
// Checks in order: /etc/xrootd/client.plugins.d/, ~/.xrootd/client.plugins.d/,
// and directory pointed to by XRD_PLUGINCONFDIR.
func getClientPluginPaths() []string {
	paths := []string{}
	configDirs := []string{}

	// Standard directories
	configDirs = append(configDirs, "/etc/xrootd/client.plugins.d/")

	// User directory
	if homeDir, err := os.UserHomeDir(); err == nil {
		configDirs = append(configDirs, filepath.Join(homeDir, ".xrootd", "client.plugins.d"))
	}

	// XRD_PLUGINCONFDIR environment variable
	if pluginConfDir := os.Getenv("XRD_PLUGINCONFDIR"); pluginConfDir != "" {
		configDirs = append(configDirs, pluginConfDir)
	}

	// Parse each directory
	for _, dir := range configDirs {
		paths = append(paths, parseClientPluginDir(dir)...)
	}

	return paths
}

// parseClientPluginDir reads plugin configuration files from a directory
// and extracts directories from absolute lib paths of enabled plugins.
func parseClientPluginDir(dir string) []string {
	paths := []string{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return paths
	}

	// Sort entries alphabetically as per xrootd behavior
	fileNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			fileNames = append(fileNames, entry.Name())
		}
	}
	sort.Strings(fileNames)

	// Process files in alphabetical order
	for _, fileName := range fileNames {
		filePath := filepath.Join(dir, fileName)
		libPath, enabled := parsePluginConfigFile(filePath)

		// Only consider paths, not filenames; linker will be handed
		// filenames and will search in standard paths.
		if enabled {
			libDir := filepath.Dir(libPath)
			// Only add if libPath contains a directory component (not just a bare filename)
			if libDir != "." && libDir != "" {
				// For absolute paths, use as-is; for relative paths, resolve against config dir
				if !filepath.IsAbs(libDir) {
					libDir = filepath.Join(dir, libDir)
				}
				paths = append(paths, libDir)
			}
		}
	}

	return paths
}

// parsePluginConfigFile parses a single plugin configuration file
// and returns the lib path and whether it's enabled.
func parsePluginConfigFile(filePath string) (string, bool) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", false
	}
	defer file.Close()

	var libPath string
	enabled := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "lib":
			libPath = value
		case "enable":
			// Accept various forms of enabled
			enabled = value == "true" || value == "1" || value == "yes"
		}
	}

	return libPath, enabled
}

// getPluginVariants returns a list of possible plugin filenames for a given base name.
// XRootD automatically adds the major version to plugin names, so libXrdHttpPelican.so
// may be libXrdHttpPelican-5.so or libXrdHttpPelican-6.so on disk.
func getPluginVariants(baseName string) []string {
	variants := []string{}

	// XRootD uses .so extension on all platforms, including macOS
	exts := []string{".so"}
	if runtime.GOOS == "darwin" {
		exts = append(exts, ".dylib")
	}

	// Strip any existing extension from baseName
	nameWithoutExt := baseName
	for _, ext := range []string{".so", ".dylib"} {
		nameWithoutExt = strings.TrimSuffix(nameWithoutExt, ext)
	}

	// Generate variants with and without version numbers
	for _, ext := range exts {
		// Base name without version
		variants = append(variants, nameWithoutExt+ext)

		// Try to get the actual XRootD version
		version := GetXrootdMajorVersion()
		if version != "" {
			// Use the detected version
			variants = append(variants, nameWithoutExt+"-"+version+ext)
		} else {
			// Fallback to common versions if we can't detect
			variants = append(variants, nameWithoutExt+"-5"+ext)
			variants = append(variants, nameWithoutExt+"-6"+ext)
		}
	}

	// XRootD will fall back to the base name if no versioned variant is found
	variants = append(variants, baseName)

	return variants
}

// checkPluginExists checks if a plugin exists in any of the standard library search paths.
// If includeClientPaths is true, also includes XRootD client plugin configuration directories.
// It returns true if the plugin is found, false otherwise.
func checkPluginExists(pluginName string, includeClientPaths bool) bool {
	searchPaths := getPluginSearchPaths()

	if includeClientPaths {
		searchPaths = append(searchPaths, getClientPluginPaths()...)
		searchPaths = deduplicatePaths(searchPaths)
	}

	variants := getPluginVariants(pluginName)

	for _, dir := range searchPaths {
		for _, name := range variants {
			fullPath := filepath.Join(dir, name)
			if _, err := os.Stat(fullPath); err == nil {
				return true
			}
		}
	}

	return false
}

// pluginPackageMap maps plugin base names (without extension) to the RPM package that provides them.
// These were determined from an OSG EL9 environment; names may differ in other distros but
// should be correct for the primary Pelican deployment targets.
var pluginPackageMap = map[string]string{
	"libXrdHttpPelican": "xrdhttp-pelican",
	"libXrdS3":          "xrootd-s3-http",
	"libXrdClPelican":   "xrdcl-pelican",
	"libXrdThrottle":    "xrootd-server-libs",
	"libXrdMacaroons":   "xrootd-server-libs",
	"libXrdMultiuser":   "xrootd-multiuser",
	"libXrdOssPosc":     "xrootd-s3-http",
	"libXrdHTTPServer":  "xrootd-s3-http",
	"libXrdOssGlobus":   "xrootd-s3-http",
	"libXrdPurgeLotMan": "xrootd-lotman",
}

// pluginBaseName strips the extension from a plugin filename (e.g. "libXrdS3.so" -> "libXrdS3").
func pluginBaseName(name string) string {
	for _, ext := range []string{".so", ".dylib"} {
		name = strings.TrimSuffix(name, ext)
	}
	return name
}

// checkAndAppendMissing checks if a plugin exists and appends it to the missing list if not found.
func checkAndAppendMissing(missingPlugins *[]string, pluginName string, includeClientPaths bool) {
	if !checkPluginExists(pluginName, includeClientPaths) {
		*missingPlugins = append(*missingPlugins, pluginName)
	}
}

// ValidateRequiredPlugins checks for the existence of required XRootD plugins based on the configuration.
// It returns an error with a detailed message if any required plugin is missing.
func ValidateRequiredPlugins(isOrigin bool, xrdConfig *XrootdConfig) error {
	missingPlugins := []string{}

	if isOrigin {
		// libXrdHttpPelican is required when drop privileges is enabled
		if xrdConfig.Server.DropPrivileges {
			checkAndAppendMissing(&missingPlugins, "libXrdHttpPelican.so", false)
		}

		// libXrdMacaroons is needed when macaroons are enabled
		if xrdConfig.Origin.EnableMacaroons {
			checkAndAppendMissing(&missingPlugins, "libXrdMacaroons.so", false)
		}

		// libXrdThrottle is needed when concurrency is configured
		if xrdConfig.Origin.Concurrency > 0 {
			checkAndAppendMissing(&missingPlugins, "libXrdThrottle.so", false)
		}

		switch xrdConfig.Origin.StorageType {
		case "posix":
			// libXrdMultiuser is needed for multiuser mode
			if xrdConfig.Origin.Multiuser {
				checkAndAppendMissing(&missingPlugins, "libXrdMultiuser.so", false)
			}
			// libXrdOssPosc is needed for atomic uploads
			if xrdConfig.Origin.EnableAtomicUploads {
				checkAndAppendMissing(&missingPlugins, "libXrdOssPosc.so", false)
			}
		case "s3":
			checkAndAppendMissing(&missingPlugins, "libXrdS3.so", false)
		case "https":
			checkAndAppendMissing(&missingPlugins, "libXrdHTTPServer.so", false)
		case "globus":
			checkAndAppendMissing(&missingPlugins, "libXrdHTTPServer.so", false)
			checkAndAppendMissing(&missingPlugins, "libXrdOssGlobus.so", false)
		}
	} else {
		// Cache-specific checks
		// libXrdHttpPelican is always required for caches (unconditional in cache template)
		checkAndAppendMissing(&missingPlugins, "libXrdHttpPelican.so", false)

		// libXrdClPelican is needed for cache servers to support pelican:// URLs.
		// Include client plugin configuration paths for this check.
		checkAndAppendMissing(&missingPlugins, "libXrdClPelican.so", true)

		// libXrdPurgeLotMan is needed when Lotman is enabled
		if xrdConfig.Cache.LotmanCfg.Enabled {
			checkAndAppendMissing(&missingPlugins, "libXrdPurgeLotMan.so", false)
		}

		// libXrdThrottle is needed when concurrency is configured
		if xrdConfig.Cache.Concurrency > 0 {
			checkAndAppendMissing(&missingPlugins, "libXrdThrottle.so", false)
		}
	}

	if len(missingPlugins) > 0 {
		searchPaths := getPluginSearchPaths()
		envVars := "LD_LIBRARY_PATH, or DYLD_LIBRARY_PATH"
		if runtime.GOOS == "darwin" {
			envVars = "DYLD_LIBRARY_PATH, or DYLD_FALLBACK_LIBRARY_PATH"
		}

		// Build per-plugin install advice, deduplicating packages
		seenPkgs := make(map[string]bool)
		var pkgAdvice []string
		for _, plugin := range missingPlugins {
			base := pluginBaseName(plugin)
			if pkg, ok := pluginPackageMap[base]; ok && !seenPkgs[pkg] {
				seenPkgs[pkg] = true
				pkgAdvice = append(pkgAdvice, pkg)
			}
		}

		var installHint string
		if len(pkgAdvice) > 0 {
			installHint = "\nThe missing plugin(s) are provided by the following package(s): " +
				strings.Join(pkgAdvice, ", ")
		}

		return errors.Errorf(
			"Required XRootD plugin(s) not found: %s\n"+
				"Please install the missing plugin(s) in one of the following directories:\n  %s\n"+
				"Or set the %s environment variable to include the plugin location.%s\n"+
				"When searching on disk, XRootD version suffixes are automatically added to the filename\n"+
				"(e.g., libXrdHttpPelican.so in config is expected to be libXrdHttpPelican-5.so on disk)",
			strings.Join(missingPlugins, ", "),
			strings.Join(searchPaths, "\n  "),
			envVars,
			installHint,
		)
	}

	return nil
}
