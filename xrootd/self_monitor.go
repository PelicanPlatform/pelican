/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const (
	selfTestBody   string = "This object was created by the Pelican self-test functionality"
	selfTestDir    string = "/pelican/monitoring/selfTest"
	selfTestPrefix string = "self-test-"
)

// Add self-test directories to xrootd data location of the cache
func InitSelfTestDir() error {
	uid, err := config.GetDaemonUID()
	if err != nil {
		return err
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	basePath := param.Cache_NamespaceLocation.GetString()
	selfTestPath := filepath.Join(basePath, selfTestDir)
	err = config.MkdirAll(selfTestPath, 0750, uid, gid)
	if err != nil {
		return errors.Wrap(err, "failed to create directory for the self-test")
	}
	log.Debugf("Created cache self-test directory at %s", selfTestPath)

	return nil
}

func generateTestFile() (string, error) {
	basePath := param.Cache_NamespaceLocation.GetString()
	if basePath == "" {
		return "", errors.New("failed to generate self-test file for cache: Cache.NamespaceLocation is not set.")
	}
	selfTestPath := filepath.Join(basePath, selfTestDir)
	_, err := os.Stat(selfTestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			uid, err := config.GetDaemonUID()
			if err != nil {
				return "", err
			}

			gid, err := config.GetDaemonGID()
			if err != nil {
				return "", err
			}

			if err := config.MkdirAll(selfTestPath, 0750, uid, gid); err != nil {
				return "", errors.Wrap(err, "failed to create self-test directory")
			}
		} else {
			return "", errors.Wrap(err, "failed to stat self-test directory")
		}
	}
	uid, err := config.GetDaemonUID()
	if err != nil {
		return "", err
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	testFileBytes := []byte(selfTestBody)
	fileSize := len(testFileBytes)
	cinfo := cache.Cinfo{
		Store: cache.Store{
			FileSize:     int64(fileSize),
			CreationTime: now.Unix(),
			Status:       2, // CSChk_None = 0
		},
	}
	cinfoBytes, err := cinfo.Serialize()
	if err != nil {
		return "", err
	}

	testFileName := selfTestPrefix + now.Format(time.RFC3339) + ".txt"
	testFileCinfoName := selfTestPrefix + now.Format(time.RFC3339) + ".txt.cinfo"

	finalFilePath := filepath.Join(selfTestPath, testFileName)

	tmpFileCinfoPath := filepath.Join(selfTestPath, testFileCinfoName+".tmp")
	finalFileCinfoPath := filepath.Join(selfTestPath, testFileCinfoName)

	// This is for web URL path, do not use filepath
	extFilePath := path.Join(selfTestDir, testFileName)

	file, err := os.OpenFile(finalFilePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create self-test file %s", finalFilePath)
	}
	defer file.Close()
	defer log.Debug("Cache self-test file created at: ", finalFilePath)

	cinfoFile, err := os.OpenFile(tmpFileCinfoPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create self-test cinfo file %s", tmpFileCinfoPath)
	}
	defer cinfoFile.Close()

	if _, err := file.Write(testFileBytes); err != nil {
		return "", errors.Wrapf(err, "failed to write test content to self-test file %s", finalFilePath)
	}
	if _, err := cinfoFile.Write(cinfoBytes); err != nil {
		return "", errors.Wrapf(err, "failed to write cinfo content to self-test cinfo file %s", tmpFileCinfoPath)
	}

	if err = file.Chown(uid, gid); err != nil {
		return "", errors.Wrapf(err, "unable to change ownership of self-test file %v to desired daemon gid %v", file, gid)
	}
	if err = cinfoFile.Chown(uid, gid); err != nil {
		return "", errors.Wrapf(err, "unable to change ownership of self-test cinfo file %v to desired daemon gid %v", file, gid)
	}

	if err := os.Rename(tmpFileCinfoPath, finalFileCinfoPath); err != nil {
		return "", errors.Wrapf(err, "unable to move self-test cinfo file from temp location %q to desired location %q", tmpFileCinfoPath, finalFileCinfoPath)
	}

	cachePort := param.Cache_Port.GetInt()
	baseUrlStr := fmt.Sprintf("https://%s:%d", param.Server_Hostname.GetString(), cachePort)
	baseUrl, err := url.Parse(baseUrlStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to validate the base url for self-test download")
	}
	baseUrl.Path = extFilePath

	if baseUrl.String() == "" {
		return "", errors.New("generated self-test file URL is empty")
	}

	return baseUrl.String(), nil
}

// generateTestFileViaPlugin creates a test file and its .cinfo file in a temp location (birthplace),
// then copies them to the selfTestDir using the xrdhttp-pelican plugin. This function is used
// when drop privileges is enabled, as the pelican server is running as an unprivileged user
// and cannot directly create files in the selfTestDir.
func generateTestFileViaPlugin() (string, error) {
	user, err := config.GetPelicanUser()
	if err != nil {
		return "", errors.Wrap(err, "failed to get user")
	}

	// Make sure the self-test directory exists.
	// This is also done in InitSelfTestDir, but we repeat it here to be robust.
	basePath := param.Cache_NamespaceLocation.GetString()
	selfTestPath := filepath.Join(basePath, selfTestDir)
	if err := os.MkdirAll(selfTestPath, 0750); err != nil {
		return "", errors.Wrap(err, "failed to create self-test directory")
	}

	// Create a temp directory own by pelican user to bypass privilege restrictions, named "birthplace"
	selfTestBirthplace := filepath.Join(param.Monitoring_DataLocation.GetString(), "selfTest")
	err = config.MkdirAll(selfTestBirthplace, 0750, user.Uid, user.Gid)
	if err != nil {
		return "", errors.Wrap(err, "failed to create self-test directory")
	}

	// Create a test file and its cinfo in the birthplace
	testFileBytes := []byte(selfTestBody)
	fileSize := len(testFileBytes)
	cinfo := cache.Cinfo{
		Store: cache.Store{
			FileSize:     int64(fileSize),
			CreationTime: time.Now().Unix(),
			Status:       2,
		},
	}
	cinfoBytes, err := cinfo.Serialize()
	if err != nil {
		return "", err
	}

	file, err := os.CreateTemp(selfTestBirthplace, selfTestPrefix+"*.txt")
	if err != nil {
		return "", errors.Wrap(err, "failed to create test file")
	}
	cinfoFile, err := os.Create(file.Name() + ".cinfo")
	if err != nil {
		return "", errors.Wrap(err, "failed to create test file cinfo")
	}
	defer func() {
		file.Close()
		cinfoFile.Close()
		// Delete the test file and its cinfo in the birthplace
		if err := os.Remove(file.Name()); err != nil {
			log.Warningf("Failed to remove test file %s: %v", file.Name(), err)
		}
		if err := os.Remove(cinfoFile.Name()); err != nil {
			log.Warningf("Failed to remove test file cinfo %s: %v", cinfoFile.Name(), err)
		}
	}()

	// Write test data and cinfo to the files
	if _, err := file.Write(testFileBytes); err != nil {
		return "", errors.Wrapf(err, "failed to write test content to self-test file %s", file.Name())
	}
	if _, err := cinfoFile.Write(cinfoBytes); err != nil {
		return "", errors.Wrapf(err, "failed to write cinfo content to self-test cinfo %s", cinfoFile.Name())
	}

	// After writing the test content to the file, the file pointer remains at the end.
	// Seek back to the beginning of the file so that the copy operation reads from the start.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", errors.Wrap(err, "failed to seek to beginning of test file")
	}
	if _, err := cinfoFile.Seek(0, io.SeekStart); err != nil {
		return "", errors.Wrap(err, "failed to seek to beginning of cinfo file")
	}

	// Transplant the test file to selfTestDir using the xrdhttp-pelican plugin.
	// Command "4" instructs the plugin to put the test file into the designated location, which is specified in `xrootd/launch.go`.
	// Check `src/XrdHttpPelican.cc` in https://github.com/PelicanPlatform/xrdhttp-pelican for the counterpart in the plugin.
	if err = FileCopyToXrootdDir(false, 4, file); err != nil {
		return "", errors.Wrap(err, "failed to copy the test file to the self-test directory")
	}
	// Transplant the cinfo file to selfTestDir using the xrdhttp-pelican plugin.
	// Command "5" instructs the plugin to put the cinfo file into the designated location, which is specified in `xrootd/launch.go`.
	if err = FileCopyToXrootdDir(false, 5, cinfoFile); err != nil {
		return "", errors.Wrap(err, "failed to copy the test cinfo file to the self-test directory")
	}

	// Construct and return the URL of the copied test file in the selfTestDir
	baseUrlStr := fmt.Sprintf("https://%s:%d", param.Server_Hostname.GetString(), param.Cache_Port.GetInt())
	baseUrl, err := url.Parse(baseUrlStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to validate the base url for self-test download")
	}
	// This is for web URL path, do not use filepath pkg.
	// The file name of the test file is always the same in the selfTestDir,
	// no matter what's the file name in the birthplace.
	extFilePath := path.Join(selfTestDir, selfTestPrefix+"cache-server.txt")
	baseUrl.Path = extFilePath

	return baseUrl.String(), nil
}

func generateFileTestScitoken() (string, error) {
	issuerUrl := param.Server_ExternalWebUrl.GetString()
	if issuerUrl == "" { // if both are empty, then error
		return "", errors.New("failed to create token: invalid iss, Server_ExternalWebUrl is empty")
	}
	fTestTokenCfg := token.NewWLCGToken()
	fTestTokenCfg.Lifetime = time.Minute
	fTestTokenCfg.Issuer = issuerUrl
	fTestTokenCfg.Subject = "cache"
	fTestTokenCfg.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/pelican/monitoring/selfTest"))
	// For self-tests, the audience is the server itself
	fTestTokenCfg.AddAudienceAny()

	// CreateToken also handles validation for us
	tok, err := fTestTokenCfg.CreateToken()
	if err != nil {
		return "", errors.Wrap(err, "failed to create file test token")
	}

	return tok, nil
}

func downloadTestFile(ctx context.Context, fileUrl string) error {
	tkn, err := generateFileTestScitoken()
	if err != nil {
		return errors.Wrap(err, "failed to create a token for cache self-test download")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileUrl, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create GET request for cache self-test download")
	}

	req.Header.Set("Authorization", "Bearer "+tkn)

	client := http.Client{Transport: config.GetTransport()}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to start request for cache self-test download")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return errors.Errorf("error response %v from cache self-test download: %v", resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to get response body from cache self-test download")
	}
	if string(body) != selfTestBody {
		return errors.Errorf("contents of cache self-test file do not match the one uploaded. Expected: %s \nGot: %s", selfTestBody, string(body))
	}

	return nil
}

func deleteTestFile(fileUrlStr string) error {
	// If drop privileges is enabled, the test file at selfTestDir will be overwritten by the next self-test,
	// because the test file and cinfo at selfTestDir always have the same name.
	// Also, the test file and cinfo in their birthplace were deleted right after generateTestFileViaPlugin,
	// so this function can be skipped.
	if param.Server_DropPrivileges.GetBool() {
		return nil
	}

	basePath := param.Cache_NamespaceLocation.GetString()
	fileUrl, err := url.Parse(fileUrlStr)
	if err != nil {
		return errors.Wrap(err, "unable to delete self-test file due to invalid URL")
	}
	relativePath := fileUrl.Path
	if !strings.HasPrefix(relativePath, selfTestDir) {
		return fmt.Errorf("unable to delete file '%s' because it's not a valid self-test path", relativePath)
	}
	filePath := path.Join(basePath, relativePath)
	// remove .cinfo file first
	if err := os.Remove(filePath + ".cinfo"); err != nil {
		return errors.Wrap(err, "failed to delete the self-test file's cinfo file")
	}
	// remove the self-test file
	if err := os.Remove(filePath); err != nil {
		return errors.Wrap(err, "fail to remove the self-test file")
	}

	return nil
}

func runSelfTest(ctx context.Context) (bool, error) {
	var fileUrl string
	var err error
	if param.Server_DropPrivileges.GetBool() {
		fileUrl, err = generateTestFileViaPlugin()
	} else {
		fileUrl, err = generateTestFile()
	}
	if err != nil {
		return false, errors.Wrap(err, "self-test failed when generating the file")
	}

	err = downloadTestFile(ctx, fileUrl)
	if err != nil {
		log.Warningf("Self-test download failed for file %s; err: %v", fileUrl, err)
		errDel := deleteTestFile(fileUrl)
		if errDel != nil {
			return false, errors.Wrap(errDel, "self-test failed during automatic cleanup")
		}
		return false, errors.Wrapf(err, "self-test failed during download. Automatic cleanup of file at '%s' has completed", fileUrl)
	}

	err = deleteTestFile(fileUrl)
	if err != nil {
		return false, errors.Wrap(err, "self-test failed during automatic cleanup")
	}
	return true, nil
}

// Run a cache self-test and log/record metrics with the test result
func doSelfMonitorCache(ctx context.Context) {
	log.Debug("Starting a new self-test monitoring cycle")

	ok, err := runSelfTest(ctx)
	if ok && err == nil {
		log.Debugln("Self-test monitoring cycle succeeded at", time.Now().Format(time.UnixDate))
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusOK, "Self-test monitoring cycle succeeded at "+time.Now().Format(time.RFC3339))
	} else if !ok && err == nil {
		log.Warningln("Self-test monitoring cycle failed with unknown error")
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "Self-test monitoring cycle failed with unknown err")
	} else {
		log.Warningln("Self-test monitoring cycle failed: ", err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "Self-test monitoring cycle failed: "+err.Error())
	}
}

// Run an origin self-test and log/record metrics with the test result
func doSelfMonitorOrigin(ctx context.Context) {
	log.Debug("Starting a new self-test monitoring cycle")
	fileTests := server_utils.TestFileTransferImpl{}
	issuerUrl := param.Server_ExternalWebUrl.GetString()
	ok, err := fileTests.RunTests(ctx, param.Origin_Url.GetString(), param.Origin_TokenAudience.GetString(), issuerUrl, server_utils.ServerSelfTest)
	if ok && err == nil {
		log.Debugln("Self-test monitoring cycle succeeded at", time.Now().Format(time.UnixDate))
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusOK, "Self-test monitoring cycle succeeded at "+time.Now().Format(time.RFC3339))
	} else {
		log.Warningln("Self-test monitoring cycle failed: ", err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "Self-test monitoring cycle failed: "+err.Error())
	}
}

// Start self-test monitoring of the origin/cache.  This will upload, download, and delete
// a generated filename every 15 seconds to the local origin.  On failure, it will
// set the xrootd component's status to critical.
func PeriodicSelfTest(ctx context.Context, ergp *errgroup.Group, isOrigin bool) {
	customInterval := param.Cache_SelfTestInterval.GetDuration()
	doSelfMonitor := doSelfMonitorCache
	if isOrigin {
		doSelfMonitor = doSelfMonitorOrigin
		customInterval = param.Origin_SelfTestInterval.GetDuration()
	}

	ticker := time.NewTicker(customInterval)
	firstRound := time.After(5 * time.Second)

	ergp.Go(func() error {
		defer ticker.Stop()
		for {
			select {
			case <-firstRound:
				doSelfMonitor(ctx)
			case <-ticker.C:
				doSelfMonitor(ctx)
			case <-ctx.Done():
				return nil
			}
		}
	})
}
