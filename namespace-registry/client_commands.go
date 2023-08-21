package nsregistry

import (
	"crypto/tls"

	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"net/http"
	"bytes"
	"bufio"
	"math/big"
	"encoding/base64"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
)

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
		return nil,err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	return body, nil
}

func respToJSON(body []byte) (map[string]string) {
	// Unmarshal the response body
	var respData map[string]string
	err := json.Unmarshal(body, &respData)
	if err != nil {
		panic(err)
	}
	return respData
}

func NamespaceRegisterWithIdentity(privateKeyPath string, namespaceRegistryEndpoint string, prefix string) (error) {
	data := map[string]interface{}{
		"identity_required": "true",
	}
	resp, err := makeRequest(namespaceRegistryEndpoint, "POST", data)
	if err != nil {
		return fmt.Errorf("Failed to make request: %s\n", err)
	}
	respData := respToJSON(resp)
	verificationURL := respData["verification_url"]
	deviceCode := respData["device_code"]
	fmt.Printf("Verification URL:\n%s\n", verificationURL)

	done := false
	for !done {
		data = map[string]interface{}{
			"identity_required": "true",
			"device_code": deviceCode,
		}
		resp, err = makeRequest(namespaceRegistryEndpoint, "POST", data)
		if err != nil {
			return fmt.Errorf("Failed to make request: %s\n", err)
		}
		respData = respToJSON(resp)
		if respData["status"] == "APPROVED" {
			done = true
		} else {
			fmt.Printf("Waiting for approval. Press Enter after verification.\n")
			reader := bufio.NewReader(os.Stdin)
			_, _ = reader.ReadString('\n')
		}
	}
	accessToken := respData["access_token"]
	return NamespaceRegister(privateKeyPath, namespaceRegistryEndpoint, accessToken, prefix)
}

func NamespaceRegister(privateKeyPath string, namespaceRegistryEndpoint string, accessToken string, prefix string) (error) {
	publicKey, err := config.LoadPublicKey("", privateKeyPath)
	if err != nil {
		return fmt.Errorf("Failed to retrieve public key: %w\n", err)
	}

	jwks, err := config.JWKSMap(publicKey)
	if err != nil {
		return fmt.Errorf("Failed to convert public key to JWKS: %w\n", err)
	}

	privateKey, err := config.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("Failed to load private key: %w\n", err)
	}

	clientNonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("Failed to generate client nonce: %w\n", err)
	}

	data := map[string]interface{}{
		"client_nonce": clientNonce,
		"pubkey":   fmt.Sprintf("%x", jwks["x"]),
	}

	resp, err := makeRequest(namespaceRegistryEndpoint, "POST", data)
	if err != nil {
		return fmt.Errorf("Failed to make request: %w\n", err)
	}
	respData := respToJSON(resp)

	// Create client payload by concatenating client_nonce and server_nonce
	clientPayload := clientNonce + respData["server_nonce"]

	// Sign the payload
	signature, err := signPayload([]byte(clientPayload), privateKey)
	if err != nil {
		return fmt.Errorf("Failed to sign payload: %w\n", err)
	}

	// Create data for the second POST request
	xBytes, _ := base64.RawURLEncoding.DecodeString(jwks["x"])
	yBytes, _ := base64.RawURLEncoding.DecodeString(jwks["y"])

	data2 := map[string]interface{}{
		"client_nonce":      clientNonce,
		"server_nonce":      respData["server_nonce"],
		"pubkey":        	 map[string]string{
			"x" : new(big.Int).SetBytes(xBytes).String(),
			"y" : new(big.Int).SetBytes(yBytes).String(),
			"curve": jwks["crv"],
		},
		"client_payload":    clientPayload,
		"client_signature":  hex.EncodeToString(signature),
		"server_payload":    respData["server_payload"],
		"server_signature":  respData["server_signature"],
		"prefix":            prefix,
		"access_token":      accessToken,
	}

	// Send the second POST request
	_, err = makeRequest(namespaceRegistryEndpoint, "POST", data2)
	if err != nil {
		return fmt.Errorf("Failed to make request: %w\n", err)
	}
	return nil
}

func NamespaceList(endpoint string) (error) {
	respData, err := makeRequest(endpoint, "GET", nil)
	if err != nil {
		return fmt.Errorf("Failed to make request: %w\n", err)
	}
	fmt.Println(string(respData))
	return nil
}

func NamespaceGet(endpoint string) (error) {
	respData, err := makeRequest(endpoint, "GET", nil)
	if err != nil {
		return fmt.Errorf("Failed to make request: %w\n", err)
	}
	fmt.Println(string(respData))
	return nil
}

func NamespaceDelete(endpoint string) (error) {
	respData, err := makeRequest(endpoint, "DELETE", nil)
	if err != nil {
		return fmt.Errorf("Failed to make request: %w\n", err)
	}
	fmt.Println(string(respData))
	return nil
}
