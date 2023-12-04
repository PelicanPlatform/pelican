/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"crypto/elliptic"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"os/exec"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/origin_ui"
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func originMockup(t *testing.T) context.CancelFunc {
	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPath := "/tmp/XRootD-Test_Origin"
	viper.Set("ConfigDir", tmpPath)
	viper.Set("Xrootd.RunLocation", filepath.Join(tmpPath, "xrootd"))
	t.Cleanup(func() {
		os.RemoveAll(tmpPath)
	})
	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()
	err := config.InitServer()

	require.NoError(t, err)

	err = config.GeneratePrivateKey(param.Server_TLSKey.GetString(), elliptic.P256())
	require.NoError(t, err)
	err = config.GenerateCert()
	require.NoError(t, err)

	err = CheckXrootdEnv(true, nil)
	require.NoError(t, err)

	err = SetUpMonitoring()
	require.NoError(t, err)

	configPath, err := ConfigXrootd(true)
	require.NoError(t, err)

	launchers, err := ConfigureLaunchers(false, configPath, false)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = daemon.LaunchDaemons(ctx, launchers)
	}()
	return cancel

}

func TestOrigin(t *testing.T) {
	viper.Reset()

	viper.Set("Origin.ExportVolume", t.TempDir()+":/test")
	viper.Set("Origin.Mode", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("TLSSkipVerify", true)

	cancel := originMockup(t)
	defer cancel()

	testExpiry := time.Now().Add(10 * time.Second)
	testSuccess := false
	for !(testSuccess || time.Now().After(testExpiry)) {
		time.Sleep(50 * time.Millisecond)
		req, err := http.NewRequest("GET", param.Origin_Url.GetString(), nil)
		require.NoError(t, err)
		httpClient := http.Client{
			Transport: config.GetTransport(),
			Timeout:   50 * time.Millisecond,
		}
		_, err = httpClient.Do(req)
		if err != nil {
			log.Infoln("Failed to send request to XRootD; likely, server is not up (will retry in 50ms):", err)
		} else {
			testSuccess = true
			log.Debugln("XRootD server appears to be functioning; will proceed with test")
		}
	}

	if testSuccess {
		url, err := origin_ui.UploadTestfile()
		require.NoError(t, err)
		err = origin_ui.DownloadTestfile(url)
		require.NoError(t, err)
		err = origin_ui.DeleteTestfile(url)
		require.NoError(t, err)
	} else {
		t.Fatalf("Unsucessful test: timeout when trying to send request to xrootd")
	}
	viper.Reset()
}

func TestS3OriginConfig(t *testing.T) {
	viper.Reset()
	tmpDir := t.TempDir()

	// We need to start up a minio server. Open to better ways to do this!
	minIOServerCmd := exec.Command("minio", "server", "--quiet", tmpDir)
	minIOServerCmd.Env = []string{fmt.Sprintf("HOME=%s", tmpDir)}

	// Create a few buffers to grab outputs
	var outb, errb bytes.Buffer
	minIOServerCmd.Stdout = &outb
	minIOServerCmd.Stderr = &errb

	err := minIOServerCmd.Start()
	// Wait for the server to initialize. Hopefully this always happens in under 2 seconds!
	time.Sleep(time.Second * 2)

	// Check for any errors in the outputs
	if strings.Contains(strings.ToLower(outb.String()), "error") {
		t.Fatalf("Could not start the MinIO server: %s", outb.String())
	} else if errb.String() != "" {
		t.Fatalf("Could not start the MinIO server: %s", errb.String())
	}
	// Check for other types of errors that might have been passed back through the process
	assert.NoError(t, err)
	defer func() {
		err = minIOServerCmd.Process.Kill()
		assert.NoError(t, err)
	}()

	// MinIO is running (by default at localhost:9000), let's create an unauthenticated bucket
	// First we set up a client instance
	endpoint := "localhost:9000"
	// By default, the endpoint will require access/secret key with these values. Note that this doesn't
	// necessarily mean the bucket we create needs those keys, as the bucket will have its own IAM
	accessKey := "minioadmin"
	secretKey := "minioadmin"
	useSSL := false

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	assert.NoError(t, err)

	// Create a new unauthenticated bucket. Under the hood, this will access the minio server endpoint
	// and do a PUT
	bucketName := "test-bucket"
	regionName := "test-region"
	serviceName := "test-name"
	err = minioClient.MakeBucket(context.Background(), bucketName, minio.MakeBucketOptions{})
	assert.NoError(t, err)

	// Set bucket policy for public read access
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + bucketName + `/*"]}]}`
	err = minioClient.SetBucketPolicy(context.Background(), bucketName, policy)
	assert.NoError(t, err)

	// Upload a test file to the bucket
	testFilePath := filepath.Join(tmpDir, "test-file.txt")
	content := []byte("This is the content of the test file.")
	err = os.WriteFile(testFilePath, content, 0644)
	assert.NoError(t, err)

	objectName := "test-file.txt"
	contentType := "application/octet-stream"
	_, err = minioClient.FPutObject(context.Background(), bucketName, objectName, testFilePath, minio.PutObjectOptions{ContentType: contentType})
	assert.NoError(t, err)

	// All the setup to create the S3 server, add a bucket with a publicly-readable object is done. Now onto Pelican stuff
	// Set up the origin and try to pull a file
	viper.Set("Origin.Mode", "s3")
	viper.Set("Origin.S3Region", regionName)
	viper.Set("Origin.S3Bucket", bucketName)
	viper.Set("Origin.S3ServiceName", serviceName)
	viper.Set("Origin.S3ServiceUrl", fmt.Sprintf("http://%s", endpoint))
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.SelfTest", false)
	viper.Set("TLSSkipVerify", true)

	cancel := originMockup(t)
	defer cancel()

	// FOR NOW, we consider the test a success if the origin's xrootd server boots.
	// TODO: When we've made it easier to come back and test whole pieces of this process by disentangling our
	// *serve* commands, come back and make this e2e. The reason I'm punting is that in S3 mode, we also need all
	// of the web_ui stuff initialized to export the public signing keys (as we can't export via XRootD) and we
	// need a real token. These become much easier when we have an internally workable set of commands to do so.

	// Wait for xrootd to initialize -- hopefully this always happens in 2 seconds!
	time.Sleep(2 * time.Second)
	// The file is accessed at ${OriginURL}/<service name>/<region>/<bucket>/<file>
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/%s/%s/%s", param.Origin_Url.GetString(), serviceName, regionName, bucketName, objectName), nil)
	require.NoError(t, err)
	httpClient := http.Client{
		Transport: config.GetTransport(),
	}
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)

	// Until we sort out the things we mentioned above, we should expect a 403 because we don't try to pass tokens
	// and we don't actually export any keys for token validation.
	assert.Equal(t, 403, resp.StatusCode)

	// One other quick check to do is that the namespace was correctly parsed:
	assert.Equal(t, fmt.Sprintf("/%s/%s/%s", serviceName, regionName, bucketName), param.Origin_NamespacePrefix.GetString())
	viper.Reset()
}
