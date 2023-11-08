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

package director

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	log "github.com/sirupsen/logrus"
)

type (
	DirectorTest struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	}
)

var (
	directorTestBody string = "This object was created by the Pelican director-test functionality"
)

// Generate a SciToken for test transfer to the origin. which will be
// validated by xrootd
func generateMonitoringScitoken(originUrl string) (string, error) {
	jti_bytes := make([]byte, 16)
	if _, err := rand.Read(jti_bytes); err != nil {
		return "", err
	}
	jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

	directorURL := param.Federation_DirectorUrl.GetString()
	if directorURL == "" {
		return "", errors.New("Director endpoint URL is not known")
	}

	tok, err := jwt.NewBuilder().
		Claim("scope", "storage.read:/ storage.modify:/").
		Claim("wlcg.ver", "1.0").
		JwtID(jti).
		Issuer(directorURL).
		Audience([]string{originUrl}).
		Subject("director"). // person sending the token
		Expiration(time.Now().Add(time.Minute)).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		return "", err
	}
	// Although it says that it's getting origin JWK,
	// the code seems to just retrive whichever private key in the path IssuerKey,
	// so I assume this is the smae thing for the director as well
	key, err := config.GetOriginJWK()
	if err != nil {
		return "", errors.Wrap(err, "failed to load the origin's JWK")
	}

	if key.KeyID() == "" {
		if err = jwk.AssignKeyID(key); err != nil {
			return "", errors.Wrap(err, "Failed to assign kid to the token")
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func UploadTestfile(originUrl string) (string, error) {
	tkn, err := generateMonitoringScitoken(originUrl)
	if err != nil {
		return "", errors.Wrap(err, "Failed to create a token for the diretor test upload")
	}

	uploadURL, err := url.Parse(originUrl)
	if err != nil {
		return "", errors.Wrap(err, "The origin URL is not parseable as a URL")
	}
	uploadURL.Path = "/pelican/monitoring/director-test-" + time.Now().Format(time.RFC3339) + ".txt"

	req, err := http.NewRequest("PUT", uploadURL.String(), bytes.NewBuffer([]byte(directorTestBody)))
	if err != nil {
		return "", errors.Wrap(err, "Failed to create POST request for director test upload")
	}

	req.Header.Set("Authorization", "Bearer "+tkn)

	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "Failed to start request for director test upload")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return "", errors.Errorf("Error response %v from director test upload: %v", resp.StatusCode, resp.Status)
	}

	return uploadURL.String(), nil
}

func DownloadTestfile(url string, originUrl string) error {
	tkn, err := generateMonitoringScitoken(originUrl)
	if err != nil {
		return errors.Wrap(err, "Failed to create a token for the director test download")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create GET request for director test download")
	}
	req.Header.Set("Authorization", "Bearer "+tkn)

	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for director test download")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failed to get response body from director test download")
	}
	if string(body) != directorTestBody {
		return errors.Errorf("Contents of self-test body do not match upload: %v", body)
	}

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from director test download: %v", resp.StatusCode, resp.Status)
	}

	return nil
}

func DeleteTestfile(url string, originUrl string) error {
	tkn, err := generateMonitoringScitoken(originUrl)
	if err != nil {
		return errors.Wrap(err, "Failed to create a token for the director test deletion")
	}

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create DELETE request for director test deletion")
	}
	req.Header.Set("Authorization", "Bearer "+tkn)

	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for director test deletion")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from director test deletion: %v", resp.StatusCode, resp.Status)
	}

	return nil
}

// Report the health status of test file transfer to origin
func reportStatusToOrigin(originWebUrl string, status string, message string) error {
	tkn, err := CreateDirectorTestReportToken(originWebUrl)
	if err != nil {
		return errors.Wrap(err, "Failed to create a token for the diretor test upload")
	}

	reportUrl, err := url.Parse(originWebUrl)
	if err != nil {
		return errors.Wrap(err, "The origin URL is not parseable as a URL")
	}

	if status != "ok" && status != "error" {
		return errors.Errorf("Bad status for reporting director test")
	}

	reportUrl.Path = "/api/v1.0/origin-api/directorTest"

	dt := DirectorTest{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(dt)
	if err != nil {
		// handle error
		return errors.Wrap(err, "Failed to parse request body for reporting director test")
	}

	reqBody := bytes.NewBuffer(jsonData)

	req, err := http.NewRequest("POST", reportUrl.String(), reqBody)
	if err != nil {
		return errors.Wrap(err, "Failed to create POST request for reporting director test")
	}

	req.Header.Set("Authorization", "Bearer "+tkn)
	req.Header.Set("Content-Type", "application/json")

	tr := config.GetTransport()
	client := http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for reporting director test")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failed to read response body for reporting director test")
	}

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from reporting director test: %v", resp.StatusCode, string(body))
	}

	return nil
}

// Run a periodic test file transfer against an origin to ensure
// it's talking to the director
func PeriodicDirectorTest(ctx context.Context, originAd ServerAd) {
	originName := originAd.Name
	originUrl := originAd.URL.String()
	originWebUrl := originAd.WebURL.String()

	log.Debug(fmt.Sprintf("Starting Director test for origin %s at %s", originName, originUrl))
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Debug(fmt.Sprintf("End director test cycle for origin: %s at %s", originName, originUrl))
			return
		case <-ticker.C:
			log.Debug(fmt.Sprintf("Starting a new Director test cycle for origin: %s at %s", originName, originUrl))
			url, err := UploadTestfile(originUrl)
			if err != nil {
				log.Warningln("Director test cycle failed during test upload:", err)
				if err := reportStatusToOrigin(originWebUrl, "error", "Director test cycle failed during test upload: "+err.Error()); err != nil {
					log.Warningln("Failed to report director test result to origin:", err)
				}
				continue
			}

			if err = DownloadTestfile(url, originUrl); err != nil {
				log.Warningln("Director test cycle failed during test download:", err)
				if err := reportStatusToOrigin(originWebUrl, "error", "Director test cycle failed during test download: "+err.Error()); err != nil {
					log.Warningln("Failed to report director test result to origin:", err)
				}
				log.Warningln("Unable to cleanup after failed self-test download:", err)
				continue
			}

			if err = DeleteTestfile(url, originUrl); err != nil {
				log.Warningln("Director test cycle failed during test deletion:", err)
				if err := reportStatusToOrigin(originWebUrl, "error", "Director test cycle failed during test deletion: "+err.Error()); err != nil {
					log.Warningln("Failed to report director test result to origin:", err)
				}
				continue
			}

			log.Debugln("Director test cycle succeeded at", time.Now().Format(time.UnixDate))
			if err := reportStatusToOrigin(originWebUrl, "ok", "Director test cycle succeeded at "+time.Now().Format(time.RFC3339)); err != nil {
				log.Warningln("Failed to report director test result to origin:", err)
			}
		}
	}
}
