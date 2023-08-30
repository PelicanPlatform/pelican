package nsregistry

import (
	"crypto/tls"
	"github.com/pkg/errors"

	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"

	"github.com/pelicanplatform/pelican/config"
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

	jwks, err := config.JWKSMap(publicKey)
	if err != nil {
		return errors.Wrap(err, "Failed to convert public key to JWKS")
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
		"pubkey":       fmt.Sprintf("%x", jwks["x"]),
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

	// Create data for the second POST request
	xBytes, err := base64.RawURLEncoding.DecodeString(jwks["x"])
	if err != nil {
		return errors.Wrap(err, "Failed to decode jwks.x")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwks["y"])
	if err != nil {
		return errors.Wrap(err, "Failed to decode jwks.y")
	}

	unidentifiedPayload := map[string]interface{}{
		"client_nonce": clientNonce,
		"server_nonce": respData.ServerNonce,
		"pubkey": map[string]string{
			"x":     new(big.Int).SetBytes(xBytes).String(),
			"y":     new(big.Int).SetBytes(yBytes).String(),
			"curve": jwks["crv"],
		},
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
