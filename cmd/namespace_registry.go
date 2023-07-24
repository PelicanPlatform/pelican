package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"math/big"
	"net/http"
	"bytes"
	"bufio"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func loadPrivateKey(privateKeyPath string) (*ecdsa.PrivateKey, error) {
	keyInBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyInBytes)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey.(*ecdsa.PrivateKey), nil
}

func loadPublicKey(publicKeyPath string) (*ecdsa.PublicKey, error) {
	keyInBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}
	var jwks JWKS
	err = json.Unmarshal(keyInBytes, &jwks)
	if err != nil {
		return nil, err
	}
	keyData := jwks.Keys[0]  // Assumes there's at least one key
	xBytes, _ := base64.RawURLEncoding.DecodeString(keyData.X)
	yBytes, _ := base64.RawURLEncoding.DecodeString(keyData.Y)
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P521(),
		X:     x,
		Y:     y,
	}
	return publicKey, nil
}


func signPayload(payload []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
    hash := sha256.Sum256(payload)
    signature, err := privateKey.Sign(rand.Reader, hash[:], crypto.SHA256)  // Use crypto.SHA256 instead of the hash[:]
    if err != nil {
        return nil, err
    }
    return signature, nil
}

/*
func writeSignatureToFile(signature []byte, filename string) error {
	err := ioutil.WriteFile(filename, signature, 0644)
	if err != nil {
		return err
	}
	return nil
}

func loadSignatureFromFile(filename string) ([]byte, error) {
	signature, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func verifySignature(payload []byte, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}
*/

func generateNonce() (string, error) {
    nonce := make([]byte, 32)
    _, err := rand.Read(nonce)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(nonce), nil
}

func make_request(url string, method string, data map[string]interface{}) ([]byte) {
	payload, _ := json.Marshal(data)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	return body
}

func resp_to_json(body []byte) (map[string]string) {
	// Unmarshal the response body
	var respData map[string]string
	err := json.Unmarshal(body, &respData)
	if err != nil {
		panic(err)
	}
	return respData
}

func namespace_register_with_identity(publicKeyPath string, privateKeyPath string, namespaceRegistryEndpoint string, prefix string) () {
	data := map[string]interface{}{
		"identity_required": "true",
	}
	resp := make_request(namespaceRegistryEndpoint, "POST", data)
	respData := resp_to_json(resp)

	verification_url := respData["verification_url"]
	device_code := respData["device_code"]
	fmt.Printf("Verification URL: %s\n", verification_url)

	done := false
	for !done {
		data = map[string]interface{}{
			"identity_required": "true",
			"device_code": device_code,
		}
		resp = make_request(namespaceRegistryEndpoint, "POST", data)
		respData = resp_to_json(resp)

		if respData["status"] == "APPROVED" {
			done = true
		} else {
			fmt.Printf("Waiting for approval...\n")
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Press Enter after verification")
			_, _ = reader.ReadString('\n')
			// time.Sleep(60 * time.Second)
		}
	}
	access_token := respData["access_token"]
	fmt.Printf("Access token: %s\n", access_token)
	namespace_register(publicKeyPath, privateKeyPath, namespaceRegistryEndpoint, access_token, prefix)

}

func namespace_register(publicKeyPath string, privateKeyPath string, namespaceRegistryEndpoint string, access_token string, prefix string) () {
	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		fmt.Printf("Failed to load public key: %v\n", err)
		os.Exit(1)
	}

	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		fmt.Printf("Failed to load private key: %v\n", err)
		os.Exit(1)
	}

	client_nonce, err := generateNonce()
	if err != nil {
		fmt.Printf("Failed to generate nonce: %v\n", err)
		os.Exit(1)
	}

	data := map[string]interface{}{
		"client_nonce": client_nonce,
		"pubkey":   fmt.Sprintf("%x", publicKey.X.Bytes()),
	}

	resp := make_request(namespaceRegistryEndpoint, "POST", data)
	respData := resp_to_json(resp)

	// Create client payload by concatenating client_nonce and server_nonce
	clientPayload := client_nonce + respData["server_nonce"]

	// Sign the payload
	signature, err := signPayload([]byte(clientPayload), privateKey)
	if err != nil {
		panic(err)
	}

	// Create data for the second POST request
	data2 := map[string]interface{}{
		"client_nonce":      client_nonce,
		"server_nonce":      respData["server_nonce"],
		"pubkey":        	 map[string]string{
			"x": publicKey.X.String(),
			"y": publicKey.Y.String(),
			"curve": "P-521",
		},
		"client_payload":    clientPayload,
		"client_signature":  hex.EncodeToString(signature),
		"server_payload":    respData["server_payload"],
		"server_signature":  respData["server_signature"],
		"prefix":            prefix,
		"access_token":      access_token,
	}

	// Send the second POST request
	make_request(namespaceRegistryEndpoint, "POST", data2)
	fmt.Printf("Namespace registered successfully\n")
}

func list_namespaces(endpoint string) {
	respData := make_request(endpoint, "GET", nil)
	fmt.Println(string(respData))
}

func get_namespace(endpoint string) {
	respData := make_request(endpoint, "GET", nil)
	fmt.Println(string(respData))
}

func delete_namespace(endpoint string) {
	respData := make_request(endpoint, "DELETE", nil)
	fmt.Println(string(respData))
}


