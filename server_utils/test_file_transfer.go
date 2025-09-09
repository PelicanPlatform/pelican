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

// This is a utility file that provides a TestFileTransferImpl struct with a `RunTests` function
// to allow any Pelican server to issue a file transfer test to a XRootD server

package server_utils

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token"
)

type (
	TestType         string
	TestFileTransfer interface {
		generateFileTestScitoken(useFederationIssuer bool) (string, error)
		uploadTestfile(ctx context.Context, baseUrl string, testType TestType) (string, error)
		downloadTestfile(ctx context.Context, downloadUrl string) error
		deleteTestfile(ctx context.Context, fileUrl string) error
		RunTests(ctx context.Context, baseUrl string, testType TestType) (bool, error)
	}
	TestFileTransferImpl struct {
		audiences    []string
		issuerUrl    string
		testType     TestType
		testBody     string
		testFilePath string // the path to the test file folder. e.g. /pelican/monitoring/selfTest
	}
)

const (
	ServerSelfTest TestType = "self-test"     // Origin/Cache object transfer self-test
	DirectorTest   TestType = "director-test" // Director-based object transfer test
)

const MonitoringBaseNs string = "/pelican/monitoring" // The base namespace for monitoring objects

const (
	SelfTestBody     string = "This object was created by the Pelican self-test functionality"
	DirectorTestBody string = "This object was created by the Pelican director-test functionality"
)

func (t TestType) String() string {
	return string(t)
}

// This function returns a token with the federation issuer or the external web url based on the `useFederationIssuer` parameter
// This is because we have old origins that expect the external web url of the director and new ones that expect the federation issuer
// So downstream we will make two requests, one with the federation issuer and one with the external web url
func (t TestFileTransferImpl) generateFileTestScitoken(useFederationIssuer bool) (string, error) {
	// The origin/cache server is using the federation issuer to verify the token
	// See server_utils/monitor.go:HandleDirectorTestResponse
	issuerUrl := param.Federation_DiscoveryUrl.GetString()
	if !useFederationIssuer {
		issuerUrl = param.Server_ExternalWebUrl.GetString()
	}

	// This branch is only hit in the the origin self monitoring
	// See xrootd/self_monitor.go:doSelfMonitorOrigin
	if t.issuerUrl != "" { // Get from param if it's not empty
		issuerUrl = t.issuerUrl
	}
	if issuerUrl == "" { // if both are empty, then error
		return "", errors.New("failed to create token: Invalid iss, Server_ExternalWebUrl is empty")
	}

	fTestTokenCfg := token.NewWLCGToken()
	fTestTokenCfg.Lifetime = time.Minute
	fTestTokenCfg.Issuer = issuerUrl
	fTestTokenCfg.Subject = "origin"
	fTestTokenCfg.Claims = map[string]string{"scope": "storage.read:/ storage.modify:/"}
	fTestTokenCfg.AddAudiences(t.audiences...)

	// CreateToken also handles validation for us
	tok, err := fTestTokenCfg.CreateToken()
	if err != nil {
		return "", errors.Wrap(err, "failed to create file test token")
	}
	return tok, nil
}

// Generic function to make a request with a token
func doRequestWithToken(ctx context.Context, url string, tkn string, method string, requestBody string) (resp *http.Response, body string, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer([]byte(requestBody)))
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create POST request for monitoring upload")
	}
	req.Header.Set("Authorization", "Bearer "+tkn)
	client := http.Client{Transport: config.GetTransport()}
	resp, err = client.Do(req)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to start request for test file upload")
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to read response body from test file upload")
	}

	return resp, string(bodyBytes), nil
}

// Private function to upload a test file to the `baseUrl` of an exported xrootd file directory
// the test file content is based on the `testType` attribute
func (t TestFileTransferImpl) uploadTestfile(ctx context.Context, baseUrl string) (string, error) {
	tkn, err := t.generateFileTestScitoken(true)
	if err != nil {
		return "", errors.Wrap(err, "failed to create a token for test file transfer")
	}

	uploadURL, err := url.Parse(baseUrl)
	if err != nil {
		return "", errors.Wrap(err, "the baseUrl is not parseable as a URL")
	}
	// /pelican/monitoring/<selfTest|directorTest>/<self-test|director-test>-YYYY-MM-DDTHH:MM:SSZ.txt
	uploadURL = uploadURL.JoinPath(path.Join(t.testFilePath, t.testType.String()+"-"+time.Now().Format(time.RFC3339)+".txt"))

	// First try with the federation issuer token
	resp, _, err := doRequestWithToken(ctx, uploadURL.String(), tkn, http.MethodPut, t.testBody)
	if err != nil {
		return "", errors.Wrap(err, "failed to upload test file")
	}

	if resp.StatusCode > 299 {
		// If the response is not successful, try with the external web url token
		tkn, err = t.generateFileTestScitoken(false)
		if err != nil {
			return "", errors.Wrap(err, "failed to create a token for test file transfer upload")
		}
		resp, _, err = doRequestWithToken(ctx, uploadURL.String(), tkn, http.MethodPut, t.testBody)
		if err != nil {
			return "", errors.Wrap(err, "failed to upload test file")
		}
		if resp.StatusCode > 299 {
			return "", errors.Errorf("error response %v from test file upload: %v", resp.StatusCode, resp.Status)
		}
	}

	return uploadURL.String(), nil
}

// Private function to download a file from downloadUrl and make sure it matches the test file
// content based on the `testBody` attribute
func (t TestFileTransferImpl) downloadTestfile(ctx context.Context, downloadUrl string) error {
	tkn, err := t.generateFileTestScitoken(true)
	if err != nil {
		return errors.Wrap(err, "failed to create a token for test file transfer download")
	}

	resp, responseBody, err := doRequestWithToken(ctx, downloadUrl, tkn, http.MethodGet, "")
	if err != nil {
		return errors.Wrap(err, "failed to download test file")
	}

	// We first check the response code to see if the request was successful
	// If it wasn't we retry with the external web url token

	if resp.StatusCode > 299 {
		// If the response is not successful, try with the external web url token
		tkn, err = t.generateFileTestScitoken(false)
		if err != nil {
			return errors.Wrap(err, "failed to create a token for test file transfer download")
		}
		resp, responseBody, err = doRequestWithToken(ctx, downloadUrl, tkn, http.MethodGet, "")
		if err != nil {
			return errors.Wrap(err, "failed to download test file")
		}
		if resp.StatusCode > 299 {
			return errors.Errorf("error response %v from test file transfer download: %v", resp.StatusCode, resp.Status)
		}
	}

	if responseBody != t.testBody {
		return errors.Errorf("contents of test file transfer body do not match upload: %v", string(responseBody))
	}

	return nil
}

// Private function to delete a test file from `fileUrl`
func (t TestFileTransferImpl) deleteTestfile(ctx context.Context, fileUrl string) error {
	tkn, err := t.generateFileTestScitoken(true)
	if err != nil {
		return errors.Wrap(err, "failed to create a token for the test file transfer deletion")
	}

	resp, _, err := doRequestWithToken(ctx, fileUrl, tkn, http.MethodDelete, "")
	if err != nil {
		return errors.Wrap(err, "failed to create DELETE request for test file transfer deletion")
	}

	if resp.StatusCode > 299 {
		// If the response is not successful, try with the external web url token
		tkn, err = t.generateFileTestScitoken(false)
		if err != nil {
			return errors.Wrap(err, "failed to create a token for test file transfer deletion")
		}
		resp, _, err = doRequestWithToken(ctx, fileUrl, tkn, http.MethodDelete, "")
		if err != nil {
			return errors.Wrap(err, "failed to delete test file")
		}
		if resp.StatusCode > 299 {
			return errors.Errorf("error response %v from test file transfer deletion: %v", resp.StatusCode, resp.Status)
		}
	}

	return nil
}

// Run a file transfer test suite with upload/download/delete a test file from
// the server and a xrootd service. It expects `baseUrl` to be the url to the xrootd
// endpoint, `issuerUrl` be the url to issue scitoken for file transfer, and the
// test file content/name be based on `testType`
//
// Note that for this test to work, you need to have the `issuerUrl` registered in
// your xrootd as a list of trusted token issuers and the issuer is expected to follow
// WLCG rules for issuer metadata discovery and public key access
//
// Read more: https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md#token-verification
func (t TestFileTransferImpl) RunTests(ctx context.Context, baseUrl, audienceUrl, issuerUrl string, testType TestType) (bool, error) {
	t.audiences = []string{baseUrl, audienceUrl}
	t.issuerUrl = issuerUrl
	t.testType = testType
	t.testFilePath = MonitoringBaseNs

	if t.testType == ServerSelfTest {
		t.testBody = SelfTestBody
		t.testFilePath = path.Join(MonitoringBaseNs, "selfTest")
	} else if t.testType == DirectorTest {
		t.testBody = DirectorTestBody
		t.testFilePath = path.Join(MonitoringBaseNs, "directorTest")
	} else {
		return false, errors.New("unsupported testType: " + testType.String())
	}

	downloadUrl, err := t.uploadTestfile(ctx, baseUrl)
	if err != nil {
		return false, errors.Wrap(err, "test file transfer failed during upload")
	}
	err = t.downloadTestfile(ctx, downloadUrl)
	if err != nil {
		return false, errors.Wrap(err, "test file transfer failed during download")
	}
	err = t.deleteTestfile(ctx, downloadUrl)
	if err != nil {
		return false, errors.Wrap(err, "test file transfer failed during delete")
	}
	return true, nil
}

// Run a file transfer test to download a test file from
// the server and a xrootd service. It expects `cacheUrl` to be the url to the xrootd cache,
// `issuerUrl` be the url to issue  a scitoken for file transfer, `filePath“ to be the namespace
// and file name of the test file, and the test file to contain the string `body`
//
// Note that for this test to work, you need to have the `issuerUrl` registered in
// your xrootd as a list of trusted token issuers and the issuer is expected to follow
// WLCG rules for issuer metadata discovery and public key access
//
// Read more: https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md#token-verification
func (t TestFileTransferImpl) TestCacheDownload(ctx context.Context, cacheUrl, issuerUrl string, filePath string, body string) (bool, error) {
	t.audiences = []string{"https://wlcg.cern.ch/jwt/v1/any"}
	t.issuerUrl = issuerUrl
	t.testBody = body

	downloadUrl, err := url.JoinPath(cacheUrl, filePath)
	if err != nil {
		return false, errors.Wrap(err, "unable to crete download URL")
	}

	err = t.downloadTestfile(ctx, downloadUrl)
	if err != nil {
		return false, errors.Wrap(err, "test file transfer failed during download")
	}

	return true, nil
}
