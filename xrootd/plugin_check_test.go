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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPluginVariants(t *testing.T) {
	t.Run("Linux", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("Skipping Linux-specific test on non-Linux platform")
		}

		variants := getPluginVariants("libXrdHttpPelican.so")
		assert.Contains(t, variants, "libXrdHttpPelican.so")
		// Should contain at least one versioned variant
		// (either the detected version or fallback versions -5/-6)
		hasVersioned := false
		for _, v := range variants {
			if strings.Contains(v, "-5.so") || strings.Contains(v, "-6.so") {
				hasVersioned = true
				break
			}
		}
		assert.True(t, hasVersioned, "Should contain at least one versioned variant")
		assert.NotContains(t, variants, "libXrdHttpPelican.dylib")
	})

	t.Run("macOS", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("Skipping macOS-specific test on non-macOS platform")
		}

		variants := getPluginVariants("libXrdHttpPelican.so")
		// XRootD uses .so extension even on macOS
		assert.Contains(t, variants, "libXrdHttpPelican.so")
		// Should contain at least one versioned variant
		hasVersioned := false
		for _, v := range variants {
			if strings.Contains(v, "-5.so") || strings.Contains(v, "-6.so") {
				hasVersioned = true
				break
			}
		}
		assert.True(t, hasVersioned, "Should contain at least one versioned variant")
	})

	t.Run("WithoutExtension", func(t *testing.T) {
		variants := getPluginVariants("libXrdS3")
		// Should generate proper variants based on platform
		assert.True(t, len(variants) > 0)
	})
}

func TestGetPluginSearchPaths(t *testing.T) {
	// Save original env vars
	originalLdLibraryPath := os.Getenv("LD_LIBRARY_PATH")
	originalDyldLibraryPath := os.Getenv("DYLD_LIBRARY_PATH")
	originalDyldFallbackLibraryPath := os.Getenv("DYLD_FALLBACK_LIBRARY_PATH")

	// Clean up after test
	defer func() {
		os.Setenv("LD_LIBRARY_PATH", originalLdLibraryPath)
		os.Setenv("DYLD_LIBRARY_PATH", originalDyldLibraryPath)
		os.Setenv("DYLD_FALLBACK_LIBRARY_PATH", originalDyldFallbackLibraryPath)
		resetPluginSearchPathsForTesting()
	}()

	t.Run("DefaultPaths", func(t *testing.T) {
		resetPluginSearchPathsForTesting()
		os.Unsetenv("LD_LIBRARY_PATH")
		os.Unsetenv("DYLD_LIBRARY_PATH")
		os.Unsetenv("DYLD_FALLBACK_LIBRARY_PATH")

		paths := getPluginSearchPaths()
		assert.True(t, len(paths) > 0, "Should have at least one default path")

		// Check for platform-specific paths
		switch runtime.GOOS {
		case "linux":
			assert.Contains(t, paths, "/usr/lib64")
		case "darwin":
			assert.Contains(t, paths, "/opt/homebrew/lib")
		}
	})

	t.Run("WithEnvironmentVariables", func(t *testing.T) {
		resetPluginSearchPathsForTesting()
		os.Unsetenv("DYLD_LIBRARY_PATH")
		os.Unsetenv("DYLD_FALLBACK_LIBRARY_PATH")

		testPath := "/custom/plugin/path"
		os.Setenv("LD_LIBRARY_PATH", testPath)

		paths := getPluginSearchPaths()
		// Convert testPath to absolute path for comparison (handles Windows paths)
		expectedPath, _ := filepath.Abs(testPath)
		expectedPath = filepath.Clean(expectedPath)
		assert.Contains(t, paths, expectedPath)
	})

	t.Run("WithMultiplePathsInEnvVar", func(t *testing.T) {
		resetPluginSearchPathsForTesting()
		os.Unsetenv("DYLD_LIBRARY_PATH")
		os.Unsetenv("DYLD_FALLBACK_LIBRARY_PATH")

		path1 := "/path/one"
		path2 := "/path/two"
		os.Setenv("LD_LIBRARY_PATH", path1+string(os.PathListSeparator)+path2)

		paths := getPluginSearchPaths()
		// Convert paths to absolute paths for comparison (handles Windows paths)
		expectedPath1, _ := filepath.Abs(path1)
		expectedPath1 = filepath.Clean(expectedPath1)
		expectedPath2, _ := filepath.Abs(path2)
		expectedPath2 = filepath.Clean(expectedPath2)
		assert.Contains(t, paths, expectedPath1)
		assert.Contains(t, paths, expectedPath2)
	})

	t.Run("WithDYLD_FALLBACK_LIBRARY_PATH", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("Skipping macOS-specific test on non-macOS platform")
		}

		resetPluginSearchPathsForTesting()
		os.Unsetenv("LD_LIBRARY_PATH")
		os.Unsetenv("DYLD_LIBRARY_PATH")

		testPath := "/fallback/lib/path"
		os.Setenv("DYLD_FALLBACK_LIBRARY_PATH", testPath)

		paths := getPluginSearchPaths()
		// Convert testPath to absolute path for comparison (handles Windows paths)
		expectedPath, _ := filepath.Abs(testPath)
		expectedPath = filepath.Clean(expectedPath)
		assert.Contains(t, paths, expectedPath)
	})
}

func TestParsePluginConfigFile(t *testing.T) {
	t.Run("ValidEnabledPlugin", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test.conf")
		content := `# Test plugin config
lib=/usr/local/lib/libTestPlugin.so
enable=true
url=pelican://
`
		err := os.WriteFile(configFile, []byte(content), 0644)
		require.NoError(t, err)

		libPath, enabled := parsePluginConfigFile(configFile)
		assert.Equal(t, "/usr/local/lib/libTestPlugin.so", libPath)
		assert.True(t, enabled)
	})

	t.Run("DisabledPlugin", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test.conf")
		content := `lib=/usr/local/lib/libTestPlugin.so
enable=false
`
		err := os.WriteFile(configFile, []byte(content), 0644)
		require.NoError(t, err)

		libPath, enabled := parsePluginConfigFile(configFile)
		assert.Equal(t, "/usr/local/lib/libTestPlugin.so", libPath)
		assert.False(t, enabled)
	})

	t.Run("EnabledVariants", func(t *testing.T) {
		for _, enableValue := range []string{"true", "1", "yes"} {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "test.conf")
			content := "lib=/test/lib.so\nenable=" + enableValue + "\n"
			err := os.WriteFile(configFile, []byte(content), 0644)
			require.NoError(t, err)

			_, enabled := parsePluginConfigFile(configFile)
			assert.True(t, enabled, "enabled=%s should be true", enableValue)
		}
	})

	t.Run("RelativePath", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test.conf")
		content := `lib=libTestPlugin.so
enable=true
`
		err := os.WriteFile(configFile, []byte(content), 0644)
		require.NoError(t, err)

		libPath, enabled := parsePluginConfigFile(configFile)
		assert.Equal(t, "libTestPlugin.so", libPath)
		assert.True(t, enabled)
	})
}

func TestParseClientPluginDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping server test on Windows - server not supported on Windows")
	}

	tmpDir := t.TempDir()

	// Create config files
	configs := map[string]string{
		"01-absolute.conf": "lib=/custom/lib/libPlugin1.so\nenable=true\n",
		"02-relative.conf": "lib=libPlugin2.so\nenable=true\n",
		"03-disabled.conf": "lib=/another/lib/libPlugin3.so\nenable=false\n",
		"04-absolute.conf": "lib=/opt/lib/libPlugin4.so\nenable=true\n",
	}

	for name, content := range configs {
		err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644)
		require.NoError(t, err)
	}

	paths := parseClientPluginDir(tmpDir)

	// Should only include directories from absolute, enabled paths
	// Convert expected paths to absolute for Windows compatibility
	expectedPath1, _ := filepath.Abs("/custom/lib")
	expectedPath1 = filepath.Clean(expectedPath1)
	expectedPath2, _ := filepath.Abs("/opt/lib")
	expectedPath2 = filepath.Clean(expectedPath2)

	assert.Contains(t, paths, expectedPath1)
	assert.Contains(t, paths, expectedPath2)
	// Should not include relative paths or disabled plugins
	assert.NotContains(t, paths, ".")

	expectedPath3, _ := filepath.Abs("/another/lib")
	expectedPath3 = filepath.Clean(expectedPath3)
	assert.NotContains(t, paths, expectedPath3)
}

func TestGetClientPluginPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping server test on Windows - server not supported on Windows")
	}

	// Save original env var
	originalPluginConfDir := os.Getenv("XRD_PLUGINCONFDIR")
	defer os.Setenv("XRD_PLUGINCONFDIR", originalPluginConfDir)

	// Create a temporary config directory
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "plugins.d")
	err := os.MkdirAll(configDir, 0755)
	require.NoError(t, err)

	// Create a test config file
	configFile := filepath.Join(configDir, "test.conf")
	content := "lib=/test/custom/lib/libPlugin.so\nenable=true\n"
	err = os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	// Set environment variable
	os.Setenv("XRD_PLUGINCONFDIR", configDir)

	paths := getClientPluginPaths()

	// Should include the custom directory
	// Convert expected path to absolute for Windows compatibility
	expectedPath, _ := filepath.Abs("/test/custom/lib")
	expectedPath = filepath.Clean(expectedPath)
	assert.Contains(t, paths, expectedPath)
}

func TestCheckClientPluginExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping server test on Windows - server not supported on Windows")
	}

	// Save original env var
	originalPluginConfDir := os.Getenv("XRD_PLUGINCONFDIR")
	defer os.Setenv("XRD_PLUGINCONFDIR", originalPluginConfDir)

	// Create a temporary config directory
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "plugins.d")
	err := os.MkdirAll(configDir, 0755)
	require.NoError(t, err)

	// Create plugin directory and plugin file
	pluginDir := filepath.Join(tmpDir, "custom", "lib")
	err = os.MkdirAll(pluginDir, 0755)
	require.NoError(t, err)

	pluginName := "libXrdClPelican-5.so"
	pluginPath := filepath.Join(pluginDir, pluginName)
	err = os.WriteFile(pluginPath, []byte("mock plugin content"), 0644)
	require.NoError(t, err)

	// Create a config file pointing to this plugin
	configFile := filepath.Join(configDir, "pelican.conf")
	content := "lib=" + pluginPath + "\nenable=true\n"
	err = os.WriteFile(configFile, []byte(content), 0644)
	require.NoError(t, err)

	// Set environment variable
	os.Setenv("XRD_PLUGINCONFDIR", configDir)

	// Should find the plugin through client plugin config
	exists := checkPluginExists("libXrdClPelican.so", true)
	assert.True(t, exists, "Should find client plugin via client plugin config")
}

func TestCheckPluginExists(t *testing.T) {
	// Save original env vars
	originalLdLibraryPath := os.Getenv("LD_LIBRARY_PATH")
	defer func() {
		os.Setenv("LD_LIBRARY_PATH", originalLdLibraryPath)
		resetPluginSearchPathsForTesting()
	}()

	// Create a temporary directory with a mock plugin
	tmpDir := t.TempDir()

	// XRootD uses .so extension on all platforms, including macOS
	pluginName := "libMockPlugin-5.so"

	mockPluginPath := filepath.Join(tmpDir, pluginName)
	err := os.WriteFile(mockPluginPath, []byte("mock plugin content"), 0644)
	require.NoError(t, err)

	// Set environment variable to include our temp directory
	resetPluginSearchPathsForTesting()
	os.Setenv("LD_LIBRARY_PATH", tmpDir)

	t.Run("PluginExists", func(t *testing.T) {
		// Should find the plugin even when searching for the base name
		exists := checkPluginExists("libMockPlugin.so", false)
		assert.True(t, exists, "Should find the versioned plugin when searching for base name")
	})

	t.Run("PluginDoesNotExist", func(t *testing.T) {
		exists := checkPluginExists("libNonExistentPlugin.so", false)
		assert.False(t, exists, "Should not find non-existent plugin")
	})
}

func TestValidateRequiredPlugins(t *testing.T) {
	t.Run("OriginWithDropPrivileges", func(t *testing.T) {
		xrdConfig := &XrootdConfig{
			Server: ServerConfig{
				DropPrivileges: true,
			},
			Origin: OriginConfig{
				StorageType: "posix",
			},
		}

		err := ValidateRequiredPlugins(true, xrdConfig)
		// This may fail if plugins are not installed, which is expected
		if err != nil {
			assert.Contains(t, err.Error(), "Required XRootD plugin(s) not found")
			assert.Contains(t, err.Error(), "libXrdHttpPelican.so")
		}
	})

	t.Run("OriginWithS3Storage", func(t *testing.T) {
		xrdConfig := &XrootdConfig{
			Server: ServerConfig{
				DropPrivileges: false,
			},
			Origin: OriginConfig{
				StorageType: "s3",
			},
		}

		err := ValidateRequiredPlugins(true, xrdConfig)
		// This may fail if plugins are not installed, which is expected
		if err != nil {
			assert.Contains(t, err.Error(), "Required XRootD plugin(s) not found")
			assert.Contains(t, err.Error(), "libXrdS3.so")
		}
	})

	t.Run("CacheWithDropPrivileges", func(t *testing.T) {
		xrdConfig := &XrootdConfig{
			Server: ServerConfig{
				DropPrivileges: true,
			},
			Cache: CacheConfig{},
		}

		err := ValidateRequiredPlugins(false, xrdConfig)
		// This may fail if plugins are not installed, which is expected
		if err != nil {
			assert.Contains(t, err.Error(), "Required XRootD plugin(s) not found")
			// Should check for both libXrdHttpPelican and libXrdClPelican
			assert.True(t,
				strings.Contains(err.Error(), "libXrdHttpPelican.so") ||
					strings.Contains(err.Error(), "libXrdClPelican.so"),
			)
		}
	})
}

func TestParseLdSoConf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Skipping Linux-specific test on non-Linux platform")
	}

	// This test checks that parseLdSoConf doesn't panic and returns some paths
	// The actual paths may vary by system
	paths := parseLdSoConf()
	// It's okay if this returns empty on systems without /etc/ld.so.conf
	// but if it does return paths, they should be absolute
	for _, path := range paths {
		assert.True(t, filepath.IsAbs(path), "All paths should be absolute")
	}
}

func TestGetXRootDRPaths(t *testing.T) {
	// This test checks that getXRootDRPaths doesn't panic
	// It may return empty if xrootd is not in PATH, which is okay
	paths := getXRootDRPaths()
	// All returned paths should be valid directories
	for _, path := range paths {
		assert.True(t, filepath.IsAbs(path), "All paths should be absolute")
	}
}

func TestGetXRootDVersion(t *testing.T) {
	// This test checks that getXRootDVersion doesn't panic
	// It may return empty if xrootd is not in PATH, which is okay
	version := getXRootDVersion()
	if version != "" {
		// If we got a version, it should be a number
		assert.Regexp(t, `^\d+$`, version, "Version should be a single digit")
	}
}
