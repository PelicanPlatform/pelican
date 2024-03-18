package cache_ui

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

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	selfTestBody string = "This object was created by the Pelican self-test functionality"
	selfTestDir  string = "/pelican/monitoring"
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

	basePath := param.Cache_DataLocation.GetString()
	pelicanMonPath := filepath.Join(basePath, "/pelican")
	monitoringPath := filepath.Join(pelicanMonPath, "/monitoring")
	err = os.MkdirAll(monitoringPath, 0700)
	if err != nil {
		return errors.Wrap(err, "Fail to create directory for the self-test")
	}
	if err = os.Chown(pelicanMonPath, uid, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of self-test /pelican directory %v to desired daemon gid %v", monitoringPath, gid)
	}
	if err = os.Chown(monitoringPath, uid, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of self-test /pelican/monitoring directory %v to desired daemon gid %v", monitoringPath, gid)
	}
	return nil
}

func generateTestFile() (string, error) {
	basePath := param.Cache_DataLocation.GetString()
	monitoringPath := filepath.Join(basePath, selfTestDir)
	_, err := os.Stat(monitoringPath)
	if err != nil {
		return "", errors.Wrap(err, "Self-test directory does not exist")
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
	cinfo := cInfo{
		Store: store{
			FileSize:     int64(fileSize),
			CreationTime: now.Unix(),
			Status:       2, // CSChk_None = 0
		},
	}
	cinfoBytes, err := cinfo.Serialize()
	if err != nil {
		return "", err
	}

	testFileName := "self-test-" + now.Format(time.RFC3339) + ".txt"
	testFileCinfoName := "self-test-" + now.Format(time.RFC3339) + ".txt.cinfo"

	finalFilePath := filepath.Join(monitoringPath, testFileName)

	tmpFileCinfoPath := filepath.Join(monitoringPath, testFileCinfoName+".tmp")
	finalFileCinfoPath := filepath.Join(monitoringPath, testFileCinfoName)

	// This is for web URL path, do not use filepath
	extFilePath := path.Join(selfTestDir, testFileName)

	file, err := os.OpenFile(finalFilePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create self-test file %s", finalFilePath)
	}
	defer file.Close()

	cinfoFile, err := os.OpenFile(tmpFileCinfoPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create self-test cinfo file %s", tmpFileCinfoPath)
	}
	defer cinfoFile.Close()

	if _, err := file.Write(testFileBytes); err != nil {
		return "", errors.Wrapf(err, "Failed to write test content to self-test file %s", finalFilePath)
	}
	if _, err := cinfoFile.Write(cinfoBytes); err != nil {
		return "", errors.Wrapf(err, "Failed to write cinfo content to self-test cinfo file %s", tmpFileCinfoPath)
	}

	if err = file.Chown(uid, gid); err != nil {
		return "", errors.Wrapf(err, "Unable to change ownership of self-test file %v to desired daemon gid %v", file, gid)
	}
	if err = cinfoFile.Chown(uid, gid); err != nil {
		return "", errors.Wrapf(err, "Unable to change ownership of self-test cinfo file %v to desired daemon gid %v", file, gid)
	}

	if err := os.Rename(tmpFileCinfoPath, finalFileCinfoPath); err != nil {
		return "", errors.Wrapf(err, "Unable to move self-test cinfo file from temp location %q to desired location %q", tmpFileCinfoPath, finalFileCinfoPath)
	}

	cachePort := param.Cache_Port.GetInt()
	baseUrlStr := fmt.Sprintf("https://%s:%d", param.Server_Hostname.GetString(), cachePort)
	baseUrl, err := url.Parse(baseUrlStr)
	if err != nil {
		return "", errors.Wrap(err, "Failed to validate the base url for self-test download")
	}
	baseUrl.Path = extFilePath

	return baseUrl.String(), nil
}

func downloadTestFile(ctx context.Context, fileUrl string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", fileUrl, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create GET request for test file transfer download")
	}

	// TODO: add auth for self-test and remove the public export in Authfile
	// once we have a local issuer up for cache (should be doable once #816 is merged)

	client := http.Client{Transport: config.GetTransport()}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for test file transfer download")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from test file transfer download: %v", resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failed to get response body from test file transfer download")
	}
	if string(body) != selfTestBody {
		return errors.Errorf("Contents of test file transfer body do not match upload: %v", body)
	}

	return nil
}

func deleteTestFile(fileUrlStr string) error {
	basePath := param.Cache_DataLocation.GetString()
	fileUrl, err := url.Parse(fileUrlStr)
	if err != nil {
		return errors.Wrap(err, "invalid file url to remove the test file")
	}
	relativePath := fileUrl.Path
	if !strings.HasPrefix(relativePath, selfTestDir) {
		return fmt.Errorf("delete request to %q is forbidden, not a self-test path", relativePath)
	}
	filePath := path.Join(basePath, relativePath)
	// remove .cinfo file first
	if err := os.Remove(filePath + ".cinfo"); err != nil {
		return errors.Wrap(err, "fail to remove the self-test file")
	}
	// remove the self-test file
	if err := os.Remove(filePath); err != nil {
		return errors.Wrap(err, "fail to remove the self-test file")
	}

	return nil
}

func runSelfTest(ctx context.Context) (bool, error) {
	fileUrl, err := generateTestFile()
	if err != nil {
		return false, errors.Wrap(err, "self-test failed when generating the file")
	}
	err = downloadTestFile(ctx, fileUrl)
	if err != nil {
		err = deleteTestFile(fileUrl)
		if err != nil {
			return false, errors.Wrap(err, "self-test failed during delete")
		}
		return false, errors.Wrap(err, "self-test failed during download")
	}
	err = deleteTestFile(fileUrl)
	if err != nil {
		return false, errors.Wrap(err, "self-test failed during delete")
	}
	return true, nil
}

// Run a cache self-test and log/record metrics with the test result
func doSelfMonitor(ctx context.Context) {
	log.Debug("Starting a new self-test monitoring cycle")

	ok, err := runSelfTest(ctx)
	if ok && err == nil {
		log.Debugln("Self-test monitoring cycle succeeded at", time.Now().Format(time.UnixDate))
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusOK, "Self-test monitoring cycle succeeded at "+time.Now().Format(time.RFC3339))
	} else {
		log.Warningln("Self-test monitoring cycle failed: ", err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "Self-test monitoring cycle failed: "+err.Error())
	}
}

func PeriodicCacheSelfTest(ctx context.Context, ergp *errgroup.Group) {
	firstRound := time.After(5 * time.Second)
	ergp.Go(func() error {
		customInterval := param.Cache_SelfTestInterval.GetDuration()
		if customInterval == 0 {
			customInterval = 15 * time.Second
			log.Error("Invalid config value: Cache.SelfTestInterval is 0. Fallback to 15s.")
		}
		ticker := time.NewTicker(customInterval)
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
