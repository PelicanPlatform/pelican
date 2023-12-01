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

package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
)

type (
	TestType         string
	TestFileTransfer interface {
		generateFileTestScitoken(audienceUrl string) (string, error)
		UploadTestfile(baseUrl string, testType TestType) (string, error)
		DownloadTestfile(downloadUrl string) error
		DeleteTestfile(fileUrl string) error
		RunTests(baseUrl string, testType TestType) (bool, error)
	}
	TestFileTransferImpl struct {
		audienceUrl string
	}
)

const (
	OriginSelfFileTest TestType = "self-test"
	DirectorFileTest   TestType = "director-test"
)

const (
	selfTestBody     string = "This object was created by the Pelican self-test functionality"
	directorTestBody string = "This object was created by the Pelican director-test functionality"
)

func (t TestType) String() string {
	return string(t)
}

// TODO: Replace by CreateEncodedToken once it's free from main package #320
func (t TestFileTransferImpl) generateFileTestScitoken() (string, error) {
	// Issuer is whichever server that initiates the test, so it's the server itself
	issuerUrl := param.Server_ExternalWebUrl.GetString()
	if issuerUrl == "" {
		return "", errors.New("Failed to create token: Invalid iss, Server_ExternalWebUrl is empty")
	}
	jti_bytes := make([]byte, 16)
	if _, err := rand.Read(jti_bytes); err != nil {
		return "", err
	}
	jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

	tok, err := jwt.NewBuilder().
		Claim("scope", "storage.read:/ storage.modify:/").
		Claim("wlcg.ver", "1.0").
		JwtID(jti).
		Issuer(issuerUrl).
		Audience([]string{t.audienceUrl}).
		Subject("origin").
		Expiration(time.Now().Add(time.Minute)).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		return "", err
	}

	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return "", errors.Wrap(err, "Failed to load server's issuer key")
	}

	if err := jwk.AssignKeyID(key); err != nil {
		return "", errors.Wrap(err, "Failed to assign kid to the token")
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func (t TestFileTransferImpl) UploadTestfile(baseUrl string, testType TestType) (string, error) {
	tkn, err := t.generateFileTestScitoken()
	if err != nil {
		return "", errors.Wrap(err, "Failed to create a token for test file transfer")
	}

	uploadURL, err := url.Parse(baseUrl)
	if err != nil {
		return "", errors.Wrap(err, "The baseUrl is not parseable as a URL")
	}
	uploadURL.Path = "/pelican/monitoring/" + testType.String() + "-" + time.Now().Format(time.RFC3339) + ".txt"

	testBody := ""
	if testType == OriginSelfFileTest {
		testBody = selfTestBody
	} else if testType == DirectorFileTest {
		testBody = directorTestBody
	} else {
		return "", errors.New("Unsupported testType: " + testType.String())
	}
	req, err := http.NewRequest("PUT", uploadURL.String(), bytes.NewBuffer([]byte(testBody)))
	if err != nil {
		return "", errors.Wrap(err, "Failed to create POST request for monitoring upload")
	}

	req.Header.Set("Authorization", "Bearer "+tkn)

	client := http.Client{Transport: config.GetTransport()}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "Failed to start request for test file upload")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return "", errors.Errorf("Error response %v from test file upload: %v", resp.StatusCode, resp.Status)
	}

	return uploadURL.String(), nil
}

func (t TestFileTransferImpl) DownloadTestfile(downloadUrl string) error {
	tkn, err := t.generateFileTestScitoken()
	if err != nil {
		return errors.Wrap(err, "Failed to create a token for test file transfer download")
	}

	req, err := http.NewRequest("GET", downloadUrl, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create GET request for test file transfer download")
	}
	req.Header.Set("Authorization", "Bearer "+tkn)

	client := http.Client{Transport: config.GetTransport()}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for test file transfer download")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failed to get response body from test file transfer download")
	}
	if string(body) != directorTestBody {
		return errors.Errorf("Contents of test file transfer body do not match upload: %v", body)
	}

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from test file transfer download: %v", resp.StatusCode, resp.Status)
	}

	return nil
}

func (t TestFileTransferImpl) DeleteTestfile(fileUrl string) error {
	tkn, err := t.generateFileTestScitoken()
	if err != nil {
		return errors.Wrap(err, "Failed to create a token for the test file transfer deletion")
	}

	req, err := http.NewRequest("DELETE", fileUrl, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create DELETE request for test file transfer deletion")
	}
	req.Header.Set("Authorization", "Bearer "+tkn)

	client := http.Client{Transport: config.GetTransport()}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for test file transfer deletion")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from test file transfer deletion: %v", resp.StatusCode, resp.Status)
	}

	return nil
}

func (t TestFileTransferImpl) RunTests(baseUrl string, testType TestType) (bool, error) {
	t.audienceUrl = baseUrl
	downloadUrl, err := t.UploadTestfile(baseUrl, testType)
	if err != nil {
		return false, errors.Wrap(err, "Test file transfer failed during upload")
	}
	err = t.DownloadTestfile(downloadUrl)
	if err != nil {
		return false, errors.Wrap(err, "Test file transfer failed during download")
	}
	err = t.DeleteTestfile(downloadUrl)
	if err != nil {
		return false, errors.Wrap(err, "Test file transfer failed during delete")
	}
	return true, nil
}
