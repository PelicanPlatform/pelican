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

package origin_ui

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	selfTestBody string = "This object was created by the Pelican self-test functionality"
)

func generateMonitoringScitoken() (string, error) {
	originUrl := param.Origin_Url.GetString()
	if originUrl == "" {
		return "", errors.New("Internal error: the Pelican origin does not know its own URL")
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
		Issuer(originUrl).
		Audience([]string{originUrl}).
		Subject("origin").
		Expiration(time.Now().Add(time.Minute)).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		return "", err
	}

	key, err := config.GetOriginJWK()
	if err != nil {
		return "", errors.Wrap(err, "failed to load the origin's JWK")
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

func DownloadTestfile(url string) error {
	tkn, err := generateMonitoringScitoken()
	if err != nil {
		return errors.Wrap(err, "Failed to create a token for the internal monitoring download")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create GET request for monitoring download")
	}
	req.Header.Set("Authorization", "Bearer "+tkn)

	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for monitoring download")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "Failed to get response body from monitoring download")
	}
	if string(body) != selfTestBody {
		return errors.Errorf("Contents of self-test body do not match upload: %v", body)
	}

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from monitoring download: %v", resp.StatusCode, resp.Status)
	}

	return nil
}

func UploadTestfile() (string, error) {
	tkn, err := generateMonitoringScitoken()
	if err != nil {
		return "", errors.Wrap(err, "Failed to create a token for the internal monitoring upload")
	}

	uploadURL, err := url.Parse(param.Origin_Url.GetString())
	if err != nil {
		return "", errors.Wrap(err, "The origin URL is not parseable as a URL")
	}
	uploadURL.Path = "/pelican/monitoring/self-test-" + time.Now().Format(time.RFC3339) + ".txt"

	req, err := http.NewRequest("PUT", uploadURL.String(), bytes.NewBuffer([]byte(selfTestBody)))
	if err != nil {
		return "", errors.Wrap(err, "Failed to create POST request for monitoring upload")
	}

	req.Header.Set("Authorization", "Bearer "+tkn)

	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "Failed to start request for monitoring upload")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return "", errors.Errorf("Error response %v from monitoring upload: %v", resp.StatusCode, resp.Status)
	}

	return uploadURL.String(), nil
}

func DeleteTestfile(url string) error {
	tkn, err := generateMonitoringScitoken()
	if err != nil {
		return errors.Wrap(err, "Failed to create a token for the internal monitoring deletion")
	}

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create DELETE request for monitoring deletion")
	}
	req.Header.Set("Authorization", "Bearer "+tkn)

	tr := config.GetTransport()
	client := http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for monitoring deletion")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return errors.Errorf("Error response %v from monitoring deletion: %v", resp.StatusCode, resp.Status)
	}

	return nil
}

func ConfigureXrootdMonitoringDir() error {
	pelicanMonitoringPath := filepath.Join(param.Xrootd_RunLocation.GetString(),
		"export", "pelican", "monitoring")

	uid, err := config.GetDaemonUID()
	if err != nil {
		return err
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}
	username, err := config.GetDaemonUser()
	if err != nil {
		return err
	}

	err = config.MkdirAll(pelicanMonitoringPath, 0755, uid, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create pelican self-monitoring directory %v",
			pelicanMonitoringPath)
	}
	if err = os.Chown(pelicanMonitoringPath, uid, -1); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of pelican self-monitoring directory %v"+
			" to desired daemon user %v", pelicanMonitoringPath, username)
	}

	return nil
}

// Start self-test monitoring of the origin.  This will upload, download, and delete
// a generated filename every 15 seconds to the local origin.  On failure, it will
// set the xrootd component's status to critical.
func PeriodicSelfTest() {
	firstRound := true
	for {
		if firstRound {
			time.Sleep(5 * time.Second)
			firstRound = false
		} else {
			time.Sleep(15 * time.Second)
		}
		log.Debug("Starting a new self-test monitoring cycle")
		url, err := UploadTestfile()
		if err != nil {
			log.Warningln("Self-test monitoring cycle failed during test upload:", err)
			if err := metrics.SetComponentHealthStatus("xrootd", "critical", "Self-test monitoring cycle failed during test upload: "+err.Error()); err != nil {
				log.Errorln("Failed to update internal component health status:", err)
			}
			continue
		}

		downloadFailed := false
		if err = DownloadTestfile(url); err != nil {
			log.Warningln("Self-test monitoring cycle failed during test download:", err)
			if err := metrics.SetComponentHealthStatus("xrootd", "critical", "Self-test monitoring cycle failed during test download: "+err.Error()); err != nil {
				log.Errorln("Failed to update internal component health status:", err)
			}
			downloadFailed = true
			// Note we don't `continue` here; we want to attempt to delete the file!
		}

		if err = DeleteTestfile(url); err != nil {
			if downloadFailed {
				log.Warningln("Unable to cleanup after failed self-test download:", err)
				continue
			}
			log.Warningln("Self-test monitoring cycle failed during test deletion:", err)
			if err := metrics.SetComponentHealthStatus("xrootd", "critical", "Self-test monitoring cycle failed during test deletion: "+err.Error()); err != nil {
				log.Errorln("Failed to update internal component health status:", err)
			}
			continue
		}

		// All is good - note it in the health status!
		log.Debugln("Self-test monitoring cycle succeeded at", time.Now().Format(time.UnixDate))
		if err := metrics.SetComponentHealthStatus("xrootd", "ok", "Self-test monitoring cycle succeeded at "+time.Now().Format(time.RFC3339)); err != nil {
			log.Errorln("Failed to update internal component health status:", err)
		}

	}
}
