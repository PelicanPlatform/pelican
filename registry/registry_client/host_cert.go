/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package registry_client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

// hostCertTokenLifetime bounds how long the request token is valid. Short by
// design: the token is minted immediately before the request.
const hostCertTokenLifetime = 2 * time.Minute

// RequestHostCertificate obtains a host TLS certificate from the registry's
// certificate authority for the service registered under prefix.
//
// It generates a fresh host keypair and CSR, mints a short-lived JWT signed by
// registrationKey (the service's registered key) that is scoped, audience-
// pinned, and bound to that exact CSR, and posts the request to the registry.
// It returns the PEM leaf+intermediate chain and the PEM host private key
// (PKCS#8). The caller is responsible for persisting them and for trusting the
// federation root (see FetchCABundle).
//
// registryEndpoint is the registry API base, e.g.
// https://registry.example/api/v1.0/registry.
func RequestHostCertificate(ctx context.Context, registryEndpoint, prefix string, registrationKey jwk.Key) (chainPEM string, hostKeyPEM string, err error) {
	// 1. Fresh host keypair.
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to generate host private key")
	}
	hostKeyDER, err := x509.MarshalPKCS8PrivateKey(hostKey)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to marshal host private key")
	}
	hostKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: hostKeyDER}))

	// 2. CSR. The registry ignores requested SANs (it stamps the slug), so the
	//    template is empty; the CSR conveys only the host public key.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, hostKey)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to create CSR")
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// 3. Mint a CSR-bound request token signed by the registered key.
	tokenStr, err := mintHostCertToken(prefix, csrDER, registrationKey)
	if err != nil {
		return "", "", err
	}

	// 4. POST to the issuance endpoint.
	endpoint, err := url.JoinPath(registryEndpoint, server_structs.HostCertificateEndpoint)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to construct host certificate endpoint URL")
	}
	payload := map[string]interface{}{
		"prefix": prefix,
		"csr":    csrPEM,
		"token":  tokenStr,
	}
	respBody, err := utils.MakeRequest(ctx, config.GetTransport(), endpoint, "POST", payload, nil)
	if err != nil {
		var apiErr server_structs.SimpleApiResp
		if respBody != nil && json.Unmarshal(respBody, &apiErr) == nil && apiErr.Msg != "" {
			return "", "", errors.Wrapf(err, "registry refused to issue a host certificate: %s", apiErr.Msg)
		}
		return "", "", errors.Wrap(err, "host certificate request failed")
	}

	var resp server_structs.IssueHostCertResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", "", errors.Wrap(err, "failed to parse host certificate response")
	}
	if resp.Certificate == "" {
		return "", "", errors.New("registry returned an empty certificate")
	}
	return resp.Certificate, hostKeyPEM, nil
}

// mintHostCertToken builds and signs the request token binding the caller's
// registered key to this CSR.
func mintHostCertToken(prefix string, csrDER []byte, registrationKey jwk.Key) (string, error) {
	alg, err := config.SigningAlgorithmForJWK(registrationKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to determine token signing algorithm")
	}
	sum := sha256.Sum256(csrDER)
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(prefix).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(hostCertTokenLifetime)).
		Audience([]string{server_structs.HostCertAudience}).
		Claim("scope", token_scopes.Registry_RequestHostCert.String()).
		Claim(server_structs.HostCertCSRHashClaim, hex.EncodeToString(sum[:])).
		Build()
	if err != nil {
		return "", errors.Wrap(err, "failed to build host certificate request token")
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, registrationKey))
	if err != nil {
		return "", errors.Wrap(err, "failed to sign host certificate request token")
	}
	return string(signed), nil
}

// FetchCABundle retrieves the federation root certificate (PEM) served by the
// registry, which the caller must add to its trust store to validate
// certificates issued by the registry CA.
func FetchCABundle(ctx context.Context, registryEndpoint string) (rootPEM string, err error) {
	endpoint, err := url.JoinPath(registryEndpoint, server_structs.CABundleEndpoint)
	if err != nil {
		return "", errors.Wrap(err, "failed to construct CA bundle endpoint URL")
	}
	body, err := utils.MakeRequest(ctx, config.GetTransport(), endpoint, "GET", nil, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to fetch the federation CA bundle")
	}
	return string(body), nil
}
