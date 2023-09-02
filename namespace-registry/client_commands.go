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

package nsregistry

import (
	"crypto/tls"

	"github.com/pkg/errors"

	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/pelicanplatform/pelican/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type clientResponseData struct {
	VerificationURL string `json:"verification_url"`
	DeviceCode      string `json:"device_code"`
	Status          string `json:"status"`
	AccessToken     string `json:"access_token"`
	ServerNonce     string `json:"server_nonce"`
	ServerPayload   string `json:"server_payload"`
	ServerSignature string `json:"server_signature"`
	Error           string `json:"error"`
}

func makeRequest(url string, method string, data map[string]interface{}) ([]byte, error) {
	payload, _ := json.Marshal(data)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	if viper.GetBool("TLSSkipVerify") {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP response -- should be 200, else something went wrong
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return body, errors.Errorf("The URL %s replied with status code %d", url, resp.StatusCode)
	}

	return body, nil
}

func NamespaceRegisterWithIdentity(privateKeyPath string, namespaceRegistryEndpoint string, prefix string) error {
	identifiedPayload := map[string]interface{}{
		"identity_required": "true",
		"prefix":            prefix,
		// we'll also send the prefix so we can avoid more work if
		// it's also registered already

	}
	resp, err := makeRequest(namespaceRegistryEndpoint, "POST", identifiedPayload)

	var respData clientResponseData
	// Handle case where there was an error encoded in the body
	if err != nil {
		if unmarshalErr := json.Unmarshal(resp, &respData); unmarshalErr == nil { // Error creating json
			return errors.Wrapf(err, "Failed to make request: %v", respData.Error)
		}
		return errors.Wrap(err, "Failed to make request")
	}

	// no error
	if err = json.Unmarshal(resp, &respData); err != nil {
		return errors.Wrap(err, "Failure when parsing JSON response from client")
	}
	fmt.Printf("Verification URL:\n%s\n", respData.VerificationURL)

	done := false
	for !done {
		identifiedPayload = map[string]interface{}{
			"identity_required": "true",
			"device_code":       respData.DeviceCode,
		}
		resp, err = makeRequest(namespaceRegistryEndpoint, "POST", identifiedPayload)
		if err != nil {
			return errors.Wrap(err, "Failed to make request")
		}

		if err = json.Unmarshal(resp, &respData); err != nil {
			return errors.Wrap(err, "Failure when parsing JSON response from client")
		}

		if respData.Status == "APPROVED" {
			done = true
		} else {
			fmt.Println("Waiting for approval. Press Enter after verification.")
			reader := bufio.NewReader(os.Stdin)
			_, _ = reader.ReadString('\n')
		}
	}
	return NamespaceRegister(privateKeyPath, namespaceRegistryEndpoint, respData.AccessToken, prefix)
}

func NamespaceRegister(privateKeyPath string, namespaceRegistryEndpoint string, accessToken string, prefix string) error {
	publicKey, err := config.LoadPublicKey("", privateKeyPath)
	if err != nil {
		return errors.Wrap(err, "Failed to retrieve public key")
	}

	/*
	 * TODO: For now, we only allow namespace registration to occur with a single key, but
	 *       at some point we should expose an API for adding additional pubkeys to each
	 *       namespace. There is a similar TODO listed in registry.go, as the choices made
	 *       there mirror the choices made here.
	 * To enforce that we're only trying to register one key, we check the length here
	 */
	if (*publicKey).Len() > 1 {
		return errors.Errorf("Only one public key can be registered in this step, but %d were provided\n", (*publicKey).Len())
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Let's check that we can convert to JSON and get the right thing...
		jsonbuf, err := json.Marshal(publicKey)
		if err != nil {
			return errors.Wrap(err, "failed to marshal the public key into JWKS JSON")
		}
		log.Debugln("Constructed JWKS from loading public key:", string(jsonbuf))
	}

	privateKey, err := config.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return errors.Wrap(err, "Failed to load private key")
	}

	clientNonce, err := generateNonce()
	if err != nil {
		return errors.Wrap(err, "Failed to generate client nonce")
	}

	data := map[string]interface{}{
		"client_nonce": clientNonce,
		"pubkey":       publicKey,
	}

	resp, err := makeRequest(namespaceRegistryEndpoint, "POST", data)

	var respData clientResponseData
	// Handle case where there was an error encoded in the body
	if err != nil {
		if unmarshalErr := json.Unmarshal(resp, &respData); unmarshalErr == nil { // Error creating json
			return errors.Wrapf(err, "Failed to make request: %v", respData.Error)
		}
		return errors.Wrap(err, "Failed to make request")
	}

	// No error
	if err = json.Unmarshal(resp, &respData); err != nil {
		return errors.Wrap(err, "Failure when parsing JSON response from client")
	}

	// Create client payload by concatenating client_nonce and server_nonce
	clientPayload := clientNonce + respData.ServerNonce

	// Sign the payload
	signature, err := signPayload([]byte(clientPayload), privateKey)
	if err != nil {
		return errors.Wrap(err, "Failed to sign payload")
	}

	// // Create data for the second POST request
	unidentifiedPayload := map[string]interface{}{
		"client_nonce":      clientNonce,
		"server_nonce":      respData.ServerNonce,
		"pubkey":            publicKey,
		"client_payload":    clientPayload,
		"client_signature":  hex.EncodeToString(signature),
		"server_payload":    respData.ServerPayload,
		"server_signature":  respData.ServerSignature,
		"prefix":            prefix,
		"access_token":      accessToken,
		"identity_required": "false",
	}

	// Send the second POST request
	resp, err = makeRequest(namespaceRegistryEndpoint, "POST", unidentifiedPayload)

	var respData2 clientResponseData
	// Handle case where there was an error encoded in the body
	if err != nil {
		if unmarshalErr := json.Unmarshal(resp, &respData2); unmarshalErr == nil {
			return errors.Wrapf(err, "Failed to make request: %v", respData2.Error)
		}
		return errors.Wrap(err, "Failed to make request")
	}

	return nil
}

func NamespaceList(endpoint string) error {
	respData, err := makeRequest(endpoint, "GET", nil)
	var respErr clientResponseData
	if err != nil {
		if jsonErr := json.Unmarshal(respData, &respErr); jsonErr == nil { // Error creating json
			return errors.Wrapf(err, "Failed to make request: %v", respErr.Error)
		}
		return errors.Wrap(err, "Failed to make request")
	}
	fmt.Println(string(respData))
	return nil
}

func NamespaceGet(endpoint string) error {
	respData, err := makeRequest(endpoint, "GET", nil)
	var respErr clientResponseData
	if err != nil {
		if jsonErr := json.Unmarshal(respData, &respErr); jsonErr == nil { // Error creating json
			return errors.Wrapf(err, "Failed to make request: %v", respErr.Error)
		}
		return errors.Wrap(err, "Failed to make request")
	}
	fmt.Println(string(respData))
	return nil
}

func NamespaceDelete(endpoint string) error {
	respData, err := makeRequest(endpoint, "DELETE", nil)
	var respErr clientResponseData
	if err != nil {
		if unmarshalErr := json.Unmarshal(respData, &respErr); unmarshalErr == nil { // Error creating json
			return errors.Wrapf(err, "Failed to make request: %v", respErr.Error)
		}
		return errors.Wrap(err, "Failed to make request")
	}
	fmt.Println(string(respData))
	return nil
}
