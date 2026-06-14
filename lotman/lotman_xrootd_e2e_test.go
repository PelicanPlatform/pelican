//go:build !windows

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

package lotman_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// readProcMapsAsUser reads /proc/<pid>/maps with the calling thread's
// filesystem credentials temporarily switched to (uid, gid). XRootD runs as the
// unprivileged "xrootd" daemon user, and a default container's root lacks
// CAP_SYS_PTRACE, so root cannot read another user's process maps -- but a
// reader sharing the target's credentials can (no ptrace capability needed).
// The switch is per-thread (RawSyscall, not the all-threads wrapper) and the
// thread is pinned for its duration, so the rest of the process stays root.
func readProcMapsAsUser(uid, gid, pid int) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		none := ^uintptr(0) // -1: leave that id unchanged
		// Lower egid before euid (once euid is unprivileged, setgid is denied);
		// fsgid/fsuid follow egid/euid, which is what /proc access is checked
		// against (PTRACE_MODE_READ_FSCREDS).
		if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESGID, none, uintptr(gid), none); e != 0 {
			ch <- result{nil, fmt.Errorf("setresgid(%d): %v", gid, e)}
			return // leave the thread pinned; the runtime discards it
		}
		if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESUID, none, uintptr(uid), none); e != 0 {
			ch <- result{nil, fmt.Errorf("setresuid(%d): %v", uid, e)}
			return
		}
		data, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
		// Restore (saved ids are still 0, so root can be regained) and only then
		// release the thread for reuse.
		_, _, e1 := syscall.RawSyscall(syscall.SYS_SETRESUID, none, 0, none)
		_, _, e2 := syscall.RawSyscall(syscall.SYS_SETRESGID, none, 0, none)
		if e1 == 0 && e2 == 0 {
			runtime.UnlockOSThread()
		}
		ch <- result{data, readErr}
	}()
	r := <-ch
	return r.data, r.err
}

// v1PublicExportConfig is a minimal V1 (posix/XRootD) origin export with public
// reads, so objects can be pulled through the cache without minting a
// storage-read token.
const v1PublicExportConfig = `
Origin:
  StorageType: "posix"
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["PublicReads", "Reads", "Writes", "DirectReads", "Listings"]
`

// purgePluginPath returns the installed XRootD lotman purge plugin path, or ""
// if it is not present (in which case the V1 integration tests skip).
func purgePluginPath() string {
	for _, p := range []string{
		"/usr/lib64/libXrdPurgeLotMan.so",
		"/usr/lib/libXrdPurgeLotMan.so",
		"/usr/local/lib64/libXrdPurgeLotMan.so",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// useLegacyLotmanABI reports whether the Go libLotMan.so should be built with
// the old (lotman v0.0.4 / xrootd-lotman v0.0.5) C ABI so it matches the
// deployed libXrdPurgeLotMan plugin. LOTMAN_E2E_LEGACY_ABI forces the choice
// (1/0); otherwise we sniff the installed lotman header the same way the Makefile
// does -- the new ABI added an int64_t query_time to update_lot_usage_by_dir.
func useLegacyLotmanABI() bool {
	if v := os.Getenv("LOTMAN_E2E_LEGACY_ABI"); v != "" {
		return v == "1"
	}
	for _, h := range []string{
		"/usr/include/lotman.h", "/usr/include/lotman/lotman.h",
		"/usr/local/include/lotman.h", "/usr/local/include/lotman/lotman.h",
	} {
		data, err := os.ReadFile(h)
		if err != nil {
			continue
		}
		idx := strings.Index(string(data), "lotman_update_lot_usage_by_dir")
		if idx < 0 {
			continue
		}
		decl := string(data)[idx:]
		if end := strings.Index(decl, ";"); end >= 0 {
			decl = decl[:end]
		}
		return !strings.Contains(decl, "int64_t") // old ABI lacks query_time
	}
	return false // no header to sniff: assume the current ABI
}

// buildGoLotManSO builds the Go C-ABI shared library into dir and returns the
// .so path. This is the artifact `make lotman-shared` produces.
func buildGoLotManSO(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "libLotMan.so")
	args := []string{"build", "-buildmode=c-shared"}
	if useLegacyLotmanABI() {
		t.Log("building Go libLotMan.so with the legacy lotman C ABI to match the installed plugin")
		args = append(args, "-tags", "lotman_legacy_api")
	}
	args = append(args, "-o", out, "github.com/pelicanplatform/pelican/lotman/cshared")
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, "building Go libLotMan.so: %s", string(combined))
	require.FileExists(t, out)
	return out
}

// TestV1Cache_LoadsGoLotManSharedLibrary spins up a V1 (XRootD) cache with
// LotMan enabled and an LD_LIBRARY_PATH that prefers a freshly-built Go
// libLotMan.so. It then proves the XRootD process actually loaded THAT library
// (not the system one) by inspecting the process's memory maps -- i.e. the
// purge plugin (libXrdPurgeLotMan.so) successfully linked the Go-built C ABI.
func TestV1Cache_LoadsGoLotManSharedLibrary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process-map inspection requires Linux /proc")
	}
	if os.Geteuid() != 0 {
		// The test runs the cache as the xrootd daemon user and reads its
		// /proc maps via a per-thread credential switch -- both need root.
		t.Skip("requires root (drops privileges to the xrootd user and probes its /proc maps)")
	}
	if _, err := exec.LookPath("xrootd"); err != nil {
		t.Skip("xrootd binary not available")
	}
	if purgePluginPath() == "" {
		t.Skip("libXrdPurgeLotMan.so (xrootd-lotman) not installed")
	}

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Diagnostic toggle: when set, skip the Go .so override and let the purge
	// plugin load the system C++ libLotMan.so, to isolate whether a purge crash
	// is in our library or the plugin itself.
	useSystemSO := os.Getenv("LOTMAN_E2E_USE_SYSTEM_SO") == "1"

	// Build the Go C-ABI library and make the dynamic loader prefer it over the
	// system /usr/lib64/libLotMan.so when the purge plugin resolves its
	// NEEDED libLotMan.so. The library and its directory must be readable by the
	// unprivileged xrootd daemon user, or the loader silently falls back to the
	// system copy -- so use a world-traversable dir, not t.TempDir() (0700).
	// Use /tmp explicitly: os.MkdirTemp("") / t.TempDir() resolve to a deeply
	// nested, per-user path (notably on macOS) that is awkward to expose to the
	// unprivileged xrootd user.
	var soPath string
	if !useSystemSO {
		soDir, err := os.MkdirTemp("/tmp", "pelican-lotmanso-")
		require.NoError(t, err)
		require.NoError(t, os.Chmod(soDir, 0o755))
		t.Cleanup(func() { _ = os.RemoveAll(soDir) })
		soPath = buildGoLotManSO(t, soDir)
		require.NoError(t, os.Chmod(soPath, 0o644))
		origLD := os.Getenv("LD_LIBRARY_PATH")
		require.NoError(t, os.Setenv("LD_LIBRARY_PATH", soDir+string(os.PathListSeparator)+origLD))
		defer func() { _ = os.Setenv("LD_LIBRARY_PATH", origLD) }()
	}

	// Enable LotMan on the V1 (XRootD) cache. EnableV2 stays false so the cache
	// runs XRootD with the pfc purge plugin.
	require.NoError(t, param.Cache_EnableLotman.Set(true))
	// lot_home must be reachable by the unprivileged xrootd daemon user (the
	// purge plugin opens <lot_home>/lots.sqlite). t.TempDir() is 0700-owned by
	// the test user, so use a world-traversable dir under /tmp instead.
	lotHome, err := os.MkdirTemp("/tmp", "pelican-lothome-")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(lotHome, 0o777))
	t.Cleanup(func() { _ = os.RemoveAll(lotHome) })
	require.NoError(t, param.Lotman_LotHome.Set(lotHome))
	// Aggressive, small purge thresholds so the cache evicts quickly once we
	// populate it. XRootD's pfc requires base < nominal < max < lowWatermark <
	// highWatermark.
	require.NoError(t, param.Cache_FilesBaseSize.Set("128k"))
	require.NoError(t, param.Cache_FilesNominalSize.Set("256k"))
	require.NoError(t, param.Cache_FilesMaxSize.Set("512k"))
	require.NoError(t, param.Cache_LowWatermark.Set("1m"))
	require.NoError(t, param.Cache_HighWaterMark.Set("2m"))
	// Run the pfc purge thread as often as XRootD allows (its minimum is 60s) so
	// eviction happens within the test window.
	require.NoError(t, param.Cache_PurgeInterval.Set(60*time.Second))

	// Seed several reasonably-sized objects in the origin export so caching them
	// pushes the cache over its purge thresholds.
	const numObjects = 12
	const objectSize = 512 * 1024
	payload := make([]byte, objectSize)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	ft := fed_test_utils.NewFedTest(t, v1PublicExportConfig, func(storageDir string) {
		for i := 0; i < numObjects; i++ {
			p := filepath.Join(storageDir, fmt.Sprintf("evict_obj_%02d.bin", i))
			require.NoError(t, os.WriteFile(p, payload, 0644))
		}
	})
	require.NotNil(t, ft)
	require.NotEmpty(t, ft.Pids, "expected xrootd subprocess pids")

	// Requirement 1: prove the cache xrootd's purge plugin loaded OUR freshly
	// built Go libLotMan.so (read the maps with the xrootd user's credentials,
	// since the daemon runs unprivileged and root lacks CAP_SYS_PTRACE).
	if !useSystemSO {
		xrootdUID, err := config.GetDaemonUID()
		require.NoError(t, err)
		xrootdGID, err := config.GetDaemonGID()
		require.NoError(t, err)

		foundPurgePlugin := false
		loadedGoSO := false
		var lotmanMappings []string
		for _, pid := range ft.Pids {
			data, rerr := readProcMapsAsUser(xrootdUID, xrootdGID, pid)
			if rerr != nil {
				t.Logf("pid %d maps unreadable: %v", pid, rerr)
				continue
			}
			text := string(data)
			if !strings.Contains(text, "libXrdPurgeLotMan") {
				continue // not the cache xrootd
			}
			foundPurgePlugin = true
			if strings.Contains(text, soPath) {
				loadedGoSO = true
			}
			for _, line := range strings.Split(text, "\n") {
				if strings.Contains(line, "libLotMan.so") {
					fields := strings.Fields(line)
					lotmanMappings = append(lotmanMappings, fields[len(fields)-1])
				}
			}
		}
		require.True(t, foundPurgePlugin,
			"expected the cache xrootd to have the libXrdPurgeLotMan purge plugin loaded")
		require.True(t, loadedGoSO,
			"the cache's purge plugin should have loaded the Go-built %s; libLotMan.so mappings seen: %v", soPath, lotmanMappings)
	}

	// --- Requirement 2 & 3: XRootD populates the cache, and the lotman purge
	// plugin evicts once we exceed the (tiny) thresholds. ---
	require.NotEmpty(t, param.Cache_DataLocations.GetStringSlice(), "cache data location should be configured")
	cacheDataDir := param.Cache_DataLocations.GetStringSlice()[0]

	// Pull every seeded object through the cache so XRootD fetches it from the
	// origin and stores it on disk.
	cached := 0
	for i := 0; i < numObjects; i++ {
		objPath := fmt.Sprintf("/test/evict_obj_%02d.bin", i)
		if getViaCache(t, ft, objPath) {
			cached++
		}
	}
	require.Greater(t, cached, 0, "at least some objects should be retrievable through the cache")

	// Requirement 3: data was populated on disk by XRootD.
	require.Eventually(t, func() bool {
		return dirSizeBytes(cacheDataDir) > 0
	}, 30*time.Second, time.Second, "XRootD should have populated the cache data directory")
	peak := dirSizeBytes(cacheDataDir)
	t.Logf("cache data dir peaked at %d bytes across %d cached objects", peak, cached)

	// Requirement 2: the pfc purge plugin (driving libLotMan over the C ABI)
	// evicts cached data back below the high watermark. We populated well past
	// the 2m high watermark, so usage must drop.
	const highWatermarkBytes = 2 * 1024 * 1024
	// XRootD's purge check runs on a hardcoded 60s cadence
	// (XrdPfcResourceMonitor::heart_beat), independent of purgeinterval, and
	// fires regardless of cache activity. Allow a couple of cycles.
	require.Eventually(t, func() bool {
		sz := dirSizeBytes(cacheDataDir)
		return sz > 0 && sz < highWatermarkBytes
	}, 180*time.Second, 5*time.Second,
		"the lotman purge plugin should evict cached data below the high watermark (peak was %d bytes)", peak)
}

// dirSizeBytes returns the total size of regular files under dir.
func dirSizeBytes(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// getViaCache asks the director where to read objPath, then fetches it directly
// from the cache (so XRootD populates its cache from the origin). Returns true
// on a 200/206 response.
func getViaCache(t *testing.T, ft *fed_test_utils.FedTest, objPath string) bool {
	t.Helper()
	directorURL := fmt.Sprintf("https://%s:%d%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objPath)
	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, directorURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+ft.Token)

	noRedir := &http.Client{
		Transport:     config.GetTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedir.Do(req)
	if err != nil {
		return false
	}
	loc := resp.Header.Get("Location")
	_ = resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 || loc == "" {
		return false
	}

	cReq, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, loc, nil)
	require.NoError(t, err)
	cReq.Header.Set("Authorization", "Bearer "+ft.Token)
	cResp, err := (&http.Client{Transport: config.GetTransport()}).Do(cReq)
	if err != nil {
		return false
	}
	defer func() { _ = cResp.Body.Close() }()
	_, _ = io.Copy(io.Discard, cResp.Body)
	return cResp.StatusCode == http.StatusOK || cResp.StatusCode == http.StatusPartialContent
}
