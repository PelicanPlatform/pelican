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

package fed_tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// getHTTPSv2Token creates a token with read/create/modify scopes for HTTPSv2 tests.
func getHTTPSv2Token(t *testing.T) string {
	t.Helper()
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope, createScope, modScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// startWebDAVServer starts a real WebDAV server backed by the given directory,
// and returns its URL. The server is stopped when the test completes.
func startWebDAVServer(t *testing.T, root string) string {
	t.Helper()

	handler := &webdav.Handler{
		FileSystem: webdav.Dir(root),
		LockSystem: webdav.NewMemLS(),
		Logger: func(_ *http.Request, err error) {
			if err != nil {
				t.Logf("WebDAV: %v", err)
			}
		},
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// startXRootDHTTPServer starts an XRootD HTTP server whose filesystem root is
// localRoot (via oss.localroot). all.export is set to "/" so any URL path is
// accepted, but because oss.localroot confines all I/O to localRoot, the server
// cannot read or write anything outside that directory tree.
//
// Returns the base URL of the XRootD HTTP service (e.g., "http://localhost:34567").
func startXRootDHTTPServer(t *testing.T, localRoot string) string {
	t.Helper()

	// Create work directories under /tmp so they have predictable paths
	// and are accessible to the xrootd user after chown.
	cfgDir, err := os.MkdirTemp("/tmp", "xrdcfg-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(cfgDir) })

	logDir := filepath.Join(cfgDir, "log")
	adminDir := filepath.Join(cfgDir, "admin")
	pidDir := filepath.Join(cfgDir, "pid")
	for _, d := range []string{logDir, adminDir, pidDir} {
		require.NoError(t, os.MkdirAll(d, 0755))
	}

	logFile := filepath.Join(logDir, "xrootd.log")

	cfgContent := fmt.Sprintf(`all.export /
oss.localroot %s
xrd.port any
xrd.protocol http:any libXrdHttp-5.so
http.desthttps no
http.selfhttps no
http.listingdeny no
http.listingredir no
sec.protocol host
all.adminpath %s
all.pidpath %s
`, localRoot, adminDir, pidDir)

	cfgFile := filepath.Join(cfgDir, "xrootd.cfg")
	require.NoError(t, os.WriteFile(cfgFile, []byte(cfgContent), 0644))

	// Build the command. XRootD refuses to run as UID 0 (root), so when
	// running as root we drop privileges to the xrootd user via
	// SysProcAttr.Credential. Non-root runners can invoke xrootd directly.
	cmd := exec.Command("xrootd", "-c", cfgFile, "-l", logFile)
	if os.Getuid() == 0 {
		xrdUser, err := user.Lookup("xrootd")
		require.NoError(t, err, "xrootd user must exist when running as root")
		uid, err := strconv.Atoi(xrdUser.Uid)
		require.NoError(t, err)
		gid, err := strconv.Atoi(xrdUser.Gid)
		require.NoError(t, err)

		// chown the work dirs so xrootd can write to them
		require.NoError(t, chownRecursive(cfgDir, uid, gid))
		require.NoError(t, chownRecursive(localRoot, uid, gid))

		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
		}
	}

	require.NoError(t, cmd.Start(), "failed to start xrootd")
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	// Parse the port from XRootD's log output. It prints a line like:
	//   ------ xrootd anon@hostname:34567 initialization completed.
	portRe := regexp.MustCompile(`initialization completed\.\s*$`)
	addrRe := regexp.MustCompile(`anon@[^:]+:(\d+)`)
	var port string
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(logFile)
		if err != nil {
			return false
		}
		if !portRe.Match(data) {
			return false
		}
		if m := addrRe.FindSubmatch(data); m != nil {
			port = string(m[1])
			return true
		}
		return false
	}, 30*time.Second, 200*time.Millisecond, "xrootd never finished initialization")

	baseURL := fmt.Sprintf("http://localhost:%s", port)

	// Verify the server is responding
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode < 500
	}, 10*time.Second, 200*time.Millisecond, "xrootd HTTP not responding")

	return baseURL
}

// chownRecursive changes ownership of a directory tree to the given uid/gid.
func chownRecursive(dir string, uid, gid int) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

// httpsv2OriginConfig returns a Pelican origin YAML config for HTTPSv2 tests.
// The storagePrefix is the URL-path prefix on the upstream HTTP server where
// files are stored. For a Go WebDAV server this is typically "/" (the root).
// For XRootD it might be "/data" or whatever path is exported.
func httpsv2OriginConfig(httpServiceURL, storagePrefix string) string {
	return fmt.Sprintf(`
Origin:
  StorageType: httpsv2
  HttpServiceUrl: "%s"
  Exports:
    - FederationPrefix: /test
      StoragePrefix: "%s"
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, httpServiceURL, storagePrefix)
}

// --------------------------------------------------------------------------
// Test with a Go-native WebDAV server
// --------------------------------------------------------------------------

func TestHTTPSv2WebDAVOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// The Go WebDAV server needs its own root directory. We'll create it
	// up front; NewFedTest will override StoragePrefix to a temp dir,
	// but for HTTPSv2 that's the path prefix on the upstream URL (not
	// a local dir). We set StoragePrefix to "/" so the origin hits the
	// WebDAV root, and map the WebDAV server's root to the directory
	// that NewFedTest creates for us.
	//
	// Strategy: start WebDAV on a temporary dir, pass that as the
	// StoragePrefix in the config so NewFedTest won't break the mapping.
	// After NewFedTest overrides StoragePrefix, we re-point the WebDAV
	// server at the directory NewFedTest created.
	//
	// Actually simpler: we start the WebDAV server on "/" and after
	// NewFedTest we know ft.Exports[0].StoragePrefix. The WebDAV server
	// has webdav.Dir(webdavRoot), so URL path /tmp/ExportXXX/file.txt
	// maps to webdavRoot/tmp/ExportXXX/file.txt. We just need to create
	// that path structure in the webdav root.
	//
	// Simplest: use a placeholder StoragePrefix of "/data", start WebDAV
	// on a temp dir, and create a "data" subdir in it that holds test files.
	// NewFedTest will override StoragePrefix, but we handle that below.

	// Create a top-level dir for the WebDAV server
	webdavRoot := t.TempDir()
	webdavURL := startWebDAVServer(t, webdavRoot)

	// We'll configure StoragePrefix = "/data" but NewFedTest overrides it.
	// So after NewFedTest we need to create the directory structure that
	// matches the overridden StoragePrefix inside webdavRoot.
	originConfig := httpsv2OriginConfig(webdavURL, "/data")

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// NewFedTest overrode StoragePrefix to a temp path. The HTTPSv2
	// backend will use this as the URL path prefix. Since the WebDAV
	// server root is webdavRoot, URL path <storagePrefix>/foo maps to
	// webdavRoot/<storagePrefix>/foo. Create that directory structure.
	storagePrefix := ft.Exports[0].StoragePrefix
	webdavDataDir := filepath.Join(webdavRoot, storagePrefix)
	require.NoError(t, os.MkdirAll(webdavDataDir, 0755))

	// Copy the hello_world.txt that NewFedTest created into the WebDAV data dir
	hwSrc := filepath.Join(storagePrefix, "hello_world.txt")
	hwDst := filepath.Join(webdavDataDir, "hello_world.txt")
	if data, err := os.ReadFile(hwSrc); err == nil {
		require.NoError(t, os.WriteFile(hwDst, data, 0644))
	}

	testToken := getHTTPSv2Token(t)
	localTmpDir := t.TempDir()

	t.Run("UploadAndDownload", func(t *testing.T) {
		testContent := "Hello from the HTTPSv2 WebDAV federation test!"
		localFile := filepath.Join(localTmpDir, "test_file.txt")
		require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/test_file.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, uploadResults)
		assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))

		downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
		downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, downloadResults)

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(got))
	})

	t.Run("RecursiveUploadDownload", func(t *testing.T) {
		// Create nested directory structure
		sourceDir := t.TempDir()
		sourceSubdir := filepath.Join(sourceDir, "subdir")
		sourceDeepdir := filepath.Join(sourceSubdir, "deepdir")
		require.NoError(t, os.MkdirAll(sourceDeepdir, 0755))

		require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("content2"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceSubdir, "file3.txt"), []byte("content3"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceDeepdir, "file4.txt"), []byte("content4"), 0644))

		// Recursive upload
		uploadURL := fmt.Sprintf("pelican://%s:%d/test/recursive/",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		_, err := client.DoPut(ft.Ctx, sourceDir, uploadURL, true, client.WithToken(testToken))
		require.NoError(t, err, "recursive upload should succeed")

		// Recursive download
		downloadDir := t.TempDir()
		_, err = client.DoGet(ft.Ctx, uploadURL, downloadDir, true, client.WithToken(testToken))
		require.NoError(t, err, "recursive download should succeed")

		// Verify all files
		testCases := []struct {
			relativePath    string
			expectedContent string
		}{
			{"file1.txt", "content1"},
			{"file2.txt", "content2"},
			{filepath.Join("subdir", "file3.txt"), "content3"},
			{filepath.Join("subdir", "deepdir", "file4.txt"), "content4"},
		}
		for _, tc := range testCases {
			downloadedPath := filepath.Join(downloadDir, tc.relativePath)
			content, err := os.ReadFile(downloadedPath)
			require.NoError(t, err, "should be able to read %s", tc.relativePath)
			assert.Equal(t, tc.expectedContent, string(content), "content of %s should match", tc.relativePath)
		}
	})

	t.Run("Listing", func(t *testing.T) {
		// Upload a few files
		files := []string{"list_a.txt", "list_b.txt", "list_c.txt"}
		for _, name := range files {
			localFile := filepath.Join(localTmpDir, name)
			require.NoError(t, os.WriteFile(localFile, []byte("list-content-"+name), 0644))

			uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
				param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), name)
			_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
			require.NoError(t, err, "failed to upload %s", name)
		}

		listURL := fmt.Sprintf("pelican://%s:%d/test/",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
		entries, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		nameSet := make(map[string]bool)
		for _, e := range entries {
			nameSet[e.Name] = true
		}
		for _, name := range files {
			found := false
			for key := range nameSet {
				if strings.Contains(key, name) {
					found = true
					break
				}
			}
			assert.True(t, found, "listing should contain %s", name)
		}
	})
}

// --------------------------------------------------------------------------
// Test with a real XRootD HTTP server
// --------------------------------------------------------------------------

// skipIfNoXRootD skips the test if the xrootd binary is not available.
// When running as root, also checks that the xrootd user exists (needed
// because XRootD refuses to run as UID 0).
func skipIfNoXRootD(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("xrootd"); err != nil {
		t.Skip("xrootd not found on PATH; skipping XRootD-backed test")
	}
	if os.Getuid() == 0 {
		if _, err := user.Lookup("xrootd"); err != nil {
			t.Skip("xrootd user does not exist; skipping XRootD-backed test (running as root)")
		}
	}
}

func TestHTTPSv2XRootDOrigin(t *testing.T) {
	skipIfNoXRootD(t)
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create the data dir under /tmp so it's accessible to the xrootd user.
	// This becomes XRootD's oss.localroot — all I/O is confined here.
	xrdDataDir, err := os.MkdirTemp("/tmp", "xrddata-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(xrdDataDir) })
	require.NoError(t, os.Chmod(xrdDataDir, 0755))

	// When running as root, chown the data dir to the xrootd user so that
	// XRootD (which drops to that UID) can write to it.
	if os.Getuid() == 0 {
		xrdUser, err := user.Lookup("xrootd")
		require.NoError(t, err)
		uid, err := strconv.Atoi(xrdUser.Uid)
		require.NoError(t, err)
		gid, err := strconv.Atoi(xrdUser.Gid)
		require.NoError(t, err)
		require.NoError(t, chownRecursive(xrdDataDir, uid, gid))
	}

	xrootdURL := startXRootDHTTPServer(t, xrdDataDir)

	// StoragePrefix placeholder — NewFedTest will override it to a random temp path.
	originConfig := httpsv2OriginConfig(xrootdURL, "/placeholder")

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// NewFedTest overrode StoragePrefix to a temp dir (e.g. /tmp/Export0XXXXX)
	// and created hello_world.txt there, chowned to xrootd. The origin will
	// request URL paths like /<storagePrefix>/file.txt from XRootD, which maps
	// to <xrdDataDir>/<storagePrefix>/file.txt via oss.localroot. Create that
	// path inside the localroot and copy the hello_world.txt.
	storagePrefix := ft.Exports[0].StoragePrefix
	xrdExportDir := filepath.Join(xrdDataDir, storagePrefix)
	require.NoError(t, os.MkdirAll(xrdExportDir, 0755))
	hwSrc := filepath.Join(storagePrefix, "hello_world.txt")
	hwDst := filepath.Join(xrdExportDir, "hello_world.txt")
	if data, err := os.ReadFile(hwSrc); err == nil {
		require.NoError(t, os.WriteFile(hwDst, data, 0644))
	}
	// Re-chown so XRootD can access the newly created directories
	if os.Getuid() == 0 {
		xrdUser, err := user.Lookup("xrootd")
		require.NoError(t, err)
		uid, err := strconv.Atoi(xrdUser.Uid)
		require.NoError(t, err)
		gid, err := strconv.Atoi(xrdUser.Gid)
		require.NoError(t, err)
		require.NoError(t, chownRecursive(xrdDataDir, uid, gid))
	}

	testToken := getHTTPSv2Token(t)
	localTmpDir := t.TempDir()

	t.Run("UploadAndDownload", func(t *testing.T) {
		testContent := "Hello from the HTTPSv2 XRootD federation test!"
		localFile := filepath.Join(localTmpDir, "test_file.txt")
		require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/xrd_test.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, uploadResults)
		assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))

		downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
		downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, downloadResults)

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(got))
	})

	t.Run("RecursiveUploadDownload", func(t *testing.T) {
		sourceDir := t.TempDir()
		sourceSubdir := filepath.Join(sourceDir, "subdir")
		sourceDeepdir := filepath.Join(sourceSubdir, "deepdir")
		require.NoError(t, os.MkdirAll(sourceDeepdir, 0755))

		require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("xrd-content1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("xrd-content2"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceSubdir, "file3.txt"), []byte("xrd-content3"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceDeepdir, "file4.txt"), []byte("xrd-content4"), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/recursive/",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		_, err := client.DoPut(ft.Ctx, sourceDir, uploadURL, true, client.WithToken(testToken))
		require.NoError(t, err, "recursive upload should succeed")

		downloadDir := t.TempDir()
		_, err = client.DoGet(ft.Ctx, uploadURL, downloadDir, true, client.WithToken(testToken))
		require.NoError(t, err, "recursive download should succeed")

		testCases := []struct {
			relativePath    string
			expectedContent string
		}{
			{"file1.txt", "xrd-content1"},
			{"file2.txt", "xrd-content2"},
			{filepath.Join("subdir", "file3.txt"), "xrd-content3"},
			{filepath.Join("subdir", "deepdir", "file4.txt"), "xrd-content4"},
		}
		for _, tc := range testCases {
			downloadedPath := filepath.Join(downloadDir, tc.relativePath)
			content, err := os.ReadFile(downloadedPath)
			require.NoError(t, err, "should be able to read %s", tc.relativePath)
			assert.Equal(t, tc.expectedContent, string(content), "content of %s should match", tc.relativePath)
		}
	})

	t.Run("Listing", func(t *testing.T) {
		files := []string{"list_a.txt", "list_b.txt", "list_c.txt"}
		for _, name := range files {
			localFile := filepath.Join(localTmpDir, name)
			require.NoError(t, os.WriteFile(localFile, []byte("xrd-list-"+name), 0644))

			uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
				param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), name)
			_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
			require.NoError(t, err, "failed to upload %s", name)
		}

		listURL := fmt.Sprintf("pelican://%s:%d/test/",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
		entries, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		nameSet := make(map[string]bool)
		for _, e := range entries {
			nameSet[e.Name] = true
		}
		for _, name := range files {
			found := false
			for key := range nameSet {
				if strings.Contains(key, name) {
					found = true
					break
				}
			}
			assert.True(t, found, "listing should contain %s", name)
		}
	})
}
