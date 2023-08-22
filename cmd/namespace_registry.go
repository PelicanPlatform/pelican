package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"

	"github.com/pelicanplatform/pelican/config"
)

func signPayload(payload []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(payload)
	signature, err := privateKey.Sign(rand.Reader, hash[:], crypto.SHA256) // Use crypto.SHA256 instead of the hash[:]
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func generateNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

func make_request(url string, method string, data map[string]interface{}) ([]byte, error) {
	payload, _ := json.Marshal(data)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	return body, nil
}

func resp_to_json(body []byte) map[string]string {
	// Unmarshal the response body
	var respData map[string]string
	err := json.Unmarshal(body, &respData)
	if err != nil {
		panic(err)
	}
	return respData
}

func namespace_register_with_identity(privateKeyPath string, namespaceRegistryEndpoint string, prefix string) error {
	data := map[string]interface{}{
		"identity_required": "true",
	}
	resp, err := make_request(namespaceRegistryEndpoint, "POST", data)
	if err != nil {
		return fmt.Errorf("Failed to make request: %v\n", err)
	}
	respData := resp_to_json(resp)

	verification_url := respData["verification_url"]
	device_code := respData["device_code"]
	fmt.Printf("Verification URL: %s\n", verification_url)

	done := false
	for !done {
		data = map[string]interface{}{
			"identity_required": "true",
			"device_code":       device_code,
		}
		resp, err = make_request(namespaceRegistryEndpoint, "POST", data)
		if err != nil {
			return fmt.Errorf("Failed to make request: %v\n", err)
		}
		respData = resp_to_json(resp)

		if respData["status"] == "APPROVED" {
			done = true
		} else {
			fmt.Printf("Waiting for approval...\n")
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Press Enter after verification")
			_, _ = reader.ReadString('\n')
		}
	}
	access_token := respData["access_token"]
	fmt.Printf("Access token: %s\n", access_token)
	return namespace_register(privateKeyPath, namespaceRegistryEndpoint, access_token, prefix)
}

func namespace_register(privateKeyPath string, namespaceRegistryEndpoint string, access_token string, prefix string) error {
	publicKey, err := config.LoadPublicKey("", privateKeyPath)
	if err != nil {
		return fmt.Errorf("Failed to retrieve public key: %v\n", err)
	}

	jwks, err := config.JWKSMap(publicKey)
	if err != nil {
		return fmt.Errorf("Failed to convert public key to JWKS: %v\n", err)
	}

	privateKey, err := config.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("Failed to load private key: %v\n", err)
	}

	client_nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("Failed to generate client nonce: %v\n", err)
	}

	data := map[string]interface{}{
		"client_nonce": client_nonce,
		"pubkey":       fmt.Sprintf("%x", jwks["x"]),
	}

	resp, err := make_request(namespaceRegistryEndpoint, "POST", data)
	if err != nil {
		return fmt.Errorf("Failed to make request: %v\n", err)
	}
	respData := resp_to_json(resp)

	// Create client payload by concatenating client_nonce and server_nonce
	clientPayload := client_nonce + respData["server_nonce"]

	// Sign the payload
	signature, err := signPayload([]byte(clientPayload), privateKey)
	if err != nil {
		return fmt.Errorf("Failed to sign payload: %v\n", err)
	}

	// Create data for the second POST request
	xBytes, _ := base64.RawURLEncoding.DecodeString(jwks["x"])
	yBytes, _ := base64.RawURLEncoding.DecodeString(jwks["y"])

	data2 := map[string]interface{}{
		"client_nonce": client_nonce,
		"server_nonce": respData["server_nonce"],
		"pubkey": map[string]string{
			"x":     new(big.Int).SetBytes(xBytes).String(),
			"y":     new(big.Int).SetBytes(yBytes).String(),
			"curve": jwks["crv"],
		},
		"client_payload":   clientPayload,
		"client_signature": hex.EncodeToString(signature),
		"server_payload":   respData["server_payload"],
		"server_signature": respData["server_signature"],
		"prefix":           prefix,
		"access_token":     access_token,
	}

	// Send the second POST request
	_, err = make_request(namespaceRegistryEndpoint, "POST", data2)
	if err != nil {
		return fmt.Errorf("Failed to make request: %v\n", err)
	}
	return nil
}

func list_namespaces(endpoint string) error {
	respData, err := make_request(endpoint, "GET", nil)
	if err != nil {
		return fmt.Errorf("Failed to make request: %v\n", err)
	}
	fmt.Println(string(respData))
	return nil
}

func get_namespace(endpoint string) error {
	respData, err := make_request(endpoint, "GET", nil)
	if err != nil {
		return fmt.Errorf("Failed to make request: %v\n", err)
	}
	fmt.Println(string(respData))
	return nil
}

func delete_namespace(endpoint string) error {
	respData, err := make_request(endpoint, "DELETE", nil)
	if err != nil {
		return fmt.Errorf("Failed to make request: %v\n", err)
	}
	fmt.Println(string(respData))
	return nil
}
