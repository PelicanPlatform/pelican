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

package registry

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type clientResponseData struct {
	VerificationURL string `json:"verification_url"`
	DeviceCode      string `json:"device_code"`
	Status          string `json:"status"`
	AccessToken     string `json:"access_token"`
	ServerNonce     string `json:"server_nonce"`
	ServerPayload   string `json:"server_payload"`
	ServerSignature string `json:"server_signature"`
	Message         string `json:"message"`
	Error           string `json:"error"`
}

func NamespaceRegisterWithIdentity(privateKey jwk.Key, namespaceRegistryEndpoint string, prefix string) error {
	identifiedPayload := map[string]interface{}{
		"identity_required": "true",
		"prefix":            prefix,
		// we'll also send the prefix so we can avoid more work if
		// it's also registered already

	}
	resp, err := utils.MakeRequest(namespaceRegistryEndpoint, "POST", identifiedPayload, nil)

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
		resp, err = utils.MakeRequest(namespaceRegistryEndpoint, "POST", identifiedPayload, nil)
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
	return NamespaceRegister(privateKey, namespaceRegistryEndpoint, respData.AccessToken, prefix)
}

func NamespaceRegister(privateKey jwk.Key, namespaceRegistryEndpoint string, accessToken string, prefix string) error {
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return errors.Wrapf(err, "Failed to generate public key for namespace registration")
	}
	err = jwk.AssignKeyID(publicKey)
	if err != nil {
		return errors.Wrap(err, "Failed to assign key ID to public key")
	}
	if err = publicKey.Set("alg", "ES256"); err != nil {
		return errors.Wrap(err, "Failed to assign signature algorithm to public key")
	}
	keySet := jwk.NewSet()
	if err = keySet.AddKey(publicKey); err != nil {
		return errors.Wrap(err, "Failed to add public key to new JWKS")
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Let's check that we can convert to JSON and get the right thing...
		jsonbuf, err := json.Marshal(keySet)
		if err != nil {
			return errors.Wrap(err, "failed to marshal the public key into JWKS JSON")
		}
		log.Debugln("Constructed JWKS from loading public key:", string(jsonbuf))
	}

	clientNonce, err := generateNonce()
	if err != nil {
		return errors.Wrap(err, "Failed to generate client nonce")
	}

	data := map[string]interface{}{
		"client_nonce": clientNonce,
		"pubkey":       keySet,
	}

	resp, err := utils.MakeRequest(namespaceRegistryEndpoint, "POST", data, nil)

	var respData clientResponseData
	// Handle case where there was an error encoded in the body
	if err != nil {
		if unmarshalErr := json.Unmarshal(resp, &respData); unmarshalErr == nil { // Error creating json
			return errors.Wrapf(err, "Failed to make request (server message is '%v')", respData.Error)
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
	privateKeyRaw := &ecdsa.PrivateKey{}
	if err = privateKey.Raw(privateKeyRaw); err != nil {
		return errors.Wrap(err, "Failed to get an ECDSA private key")
	}
	signature, err := signPayload([]byte(clientPayload), privateKeyRaw)
	if err != nil {
		return errors.Wrap(err, "Failed to sign payload")
	}

	// // Create data for the second POST request
	unidentifiedPayload := map[string]interface{}{
		"client_nonce":      clientNonce,
		"server_nonce":      respData.ServerNonce,
		"pubkey":            keySet,
		"client_payload":    clientPayload,
		"client_signature":  hex.EncodeToString(signature),
		"server_payload":    respData.ServerPayload,
		"server_signature":  respData.ServerSignature,
		"prefix":            prefix,
		"access_token":      accessToken,
		"identity_required": "false",
	}

	// Send the second POST request
	resp, err = utils.MakeRequest(namespaceRegistryEndpoint, "POST", unidentifiedPayload, nil)

	// Handle case where there was an error encoded in the body
	if unmarshalErr := json.Unmarshal(resp, &respData); unmarshalErr == nil {
		if err != nil {
			return errors.Wrapf(err, "Failed to make request: %v", respData.Error)
		}
		fmt.Println(respData.Message)
	} else {
		if err != nil {
			return errors.Wrapf(err, "Failed to make request: %s", resp)
		}
		return errors.Wrapf(unmarshalErr, "Failed to unmarshall request response: %v", respData.Error)
	}

	return nil
}

func NamespaceList(endpoint string) error {
	respData, err := utils.MakeRequest(endpoint, "GET", nil, nil)
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
	respData, err := utils.MakeRequest(endpoint, "GET", nil, nil)
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

func NamespaceDelete(endpoint string, prefix string) error {
	// First we create a token for the registry to check that the deletion
	// request is valid

	// TODO: We might consider moving widely-useful functions like `GetRegistryIssuerURL`
	//       to a more generic `pelican/utils` package so that they're easier to find
	//       and more likely to be used.
	issuerURL, err := director.GetNSIssuerURL(prefix)
	if err != nil {
		return errors.Wrap(err, "Failed to determine prefix's issuer/pubkey URL for creating deletion token")
	}

	// TODO: Eventually we should think about a naming scheme for
	//       including an audience with these tokens.
	// TODO: Investigate whether 1 min is a good expiration interval
	//       or whether this should be altered.
	delTokenCfg := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuerURL,
		Audience:     []string{"registry"},
		Version:      "1.0",
		Subject:      "origin",
		Claims:       map[string]string{"scope": token_scopes.Pelican_NamespaceDelete.String()},
	}

	// CreateToken also handles validation for us
	tok, err := delTokenCfg.CreateToken()
	if err != nil {
		return errors.Wrap(err, "failed to create namespace deletion token")
	}

	// We're at the client, so it *should* be safe to print the signed token to
	// stdout when the client asks for debug -- a future attacker will only find
	// expired tokens, and an attacker with current access can just use the priv
	// key to create their own. Famous last words?
	log.Debugln("Signed deletion token:", tok)

	authHeader := map[string]string{
		"Authorization": "Bearer " + tok,
	}

	respData, err := utils.MakeRequest(endpoint, "DELETE", nil, authHeader)
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
