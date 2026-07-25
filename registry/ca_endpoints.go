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

// HTTP surface for the registry certificate authority (WS3). It exposes:
//
//   - POST /api/v1.0/registry/issueHostCertificate — issues a short-lived host
//     certificate to a registered, approved service. The requester authenticates
//     with a JWT signed by its *registered* private key, carrying the
//     registry.request_host_cert scope, an audience pinned to the registry CA,
//     a short expiry, and a claim binding it to the exact CSR presented. The
//     certificate is issued for the service's unique slug (never its IP).
//   - GET /api/v1.0/registry/ca.pem — the public federation root, for peers that
//     need the trust anchor. (Also advertised via federation metadata.)
//
// Why a signed JWT rather than a nonce challenge/response: a single bound token
// is simpler and strictly stronger. The critical property is that the
// authorization is bound to the CSR (via HostCertCSRHashClaim) — otherwise a
// leaked or in-flight token could be paired with an attacker's own CSR to mint a
// slug-bound certificate for the attacker's key. The token's short expiry,
// audience, and scope prevent it from being minted for, or replayed from, any
// other context.
//
// The crypto lives in ca.go; this file is only transport + policy.
package registry

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// issueHostCertificate is the gin handler.
func issueHostCertificate(ctx *gin.Context) {
	var req server_structs.IssueHostCertRequest
	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad Request: " + err.Error(),
		})
		return
	}

	chainPEM, err := issueHostCertificateImpl(&req)
	switch {
	case err == nil:
		ctx.JSON(http.StatusOK, map[string]interface{}{"certificate": chainPEM})
	case errors.As(err, &permissionDeniedError{}):
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: err.Error()})
	case errors.As(err, &badRequestError{}):
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: err.Error()})
	default:
		log.Warningf("Host certificate issuance failed: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server encountered an error issuing the host certificate"})
	}
}

// issueHostCertificateImpl holds the transport-independent logic so it can be
// unit-tested directly.
func issueHostCertificateImpl(req *server_structs.IssueHostCertRequest) (string, error) {
	if req.Prefix == "" || req.CSR == "" || req.Token == "" {
		return "", badRequestError{Message: "prefix, csr, and token are all required"}
	}

	// 1. The service must be registered AND approved.
	registration, err := requireApprovedService(req.Prefix)
	if err != nil {
		return "", err
	}

	// 2. Parse the CSR (its self-signature is checked in SignHostCertificate).
	csr, err := parseCSRPEM(req.CSR)
	if err != nil {
		return "", badRequestError{Message: err.Error()}
	}

	// 3. Authenticate: the token must be signed by the registered key, carry
	//    the request_host_cert scope + our audience, be unexpired, and be bound
	//    to this exact CSR.
	if err := verifyHostCertToken(req.Token, registration.Pubkey, csr); err != nil {
		return "", err
	}

	// 4. The certificate identity is the service's unique slug plus any DNS
	//    hostname the registration authoritatively binds to it.
	slug, err := serviceSlugForPrefix(req.Prefix)
	if err != nil {
		return "", err
	}

	// 5. Issue.
	chainPEM, err := SignHostCertificate(nil, HostCertRequest{
		CSR:             csr,
		AuthorizedNames: authorizedNamesForPrefix(req.Prefix, slug),
	})
	if err != nil {
		return "", badRequestError{Message: err.Error()}
	}
	log.Infof("Issued host certificate for prefix %s (slug %s)", req.Prefix, slug)
	return chainPEM, nil
}

// verifyHostCertToken validates the request token against the registered JWKS
// and enforces scope, audience, expiry, and CSR binding.
func verifyHostCertToken(tokenStr, pubkeyJWKS string, csr *x509.CertificateRequest) error {
	jwks, err := jwk.Parse([]byte(pubkeyJWKS))
	if err != nil {
		return errors.Wrap(err, "failed to parse the registered public key set")
	}

	scopeValidator := token_scopes.CreateScopeValidator(
		[]token_scopes.TokenScope{token_scopes.Registry_RequestHostCert}, false)

	tok, err := token.VerifyWithKeysetStrict(tokenStr, jwks,
		jwt.WithAudience(server_structs.HostCertAudience),
		jwt.WithValidator(scopeValidator),
	)
	if err != nil {
		return permissionDeniedError{Message: "request token is invalid: " + err.Error()}
	}

	// Reject tokens without an expiry — the requester must scope its authority
	// in time.
	if tok.Expiration().IsZero() {
		return permissionDeniedError{Message: "request token must carry an expiry (exp)"}
	}

	// CSR binding: the token must commit to the exact CSR presented.
	claim, ok := tok.Get(server_structs.HostCertCSRHashClaim)
	if !ok {
		return permissionDeniedError{Message: "request token is missing the CSR binding claim"}
	}
	claimStr, ok := claim.(string)
	if !ok {
		return permissionDeniedError{Message: "CSR binding claim is not a string"}
	}
	if claimStr != csrThumbprint(csr) {
		return permissionDeniedError{Message: "request token is not bound to the presented CSR"}
	}
	return nil
}

// csrThumbprint returns hex(SHA-256(CSR DER)).
func csrThumbprint(csr *x509.CertificateRequest) string {
	sum := sha256.Sum256(csr.Raw)
	return hex.EncodeToString(sum[:])
}

// requireApprovedService loads the registration for prefix and enforces the
// federation's approval policy — mirroring the issuer.jwks endpoint. An
// Approved service always qualifies; a Denied service never does; a Pending
// service qualifies only when the federation does not require approval for that
// service type (Registry.RequireOriginApproval / Registry.RequireCacheApproval).
// This keeps certificate issuance consistent with the rest of the registry and
// avoids adding an approval requirement a federation hasn't opted into.
func requireApprovedService(prefix string) (*server_structs.Registration, error) {
	registration, err := getRegistrationByPrefix(prefix)
	if err != nil {
		return nil, permissionDeniedError{Message: "no registration found for prefix " + prefix}
	}
	switch registration.AdminMetadata.Status {
	case server_structs.RegApproved:
		return registration, nil
	case server_structs.RegDenied:
		return nil, permissionDeniedError{Message: "registration for " + prefix + " has been denied"}
	default: // Pending (or unset)
		requiresApproval := param.Registry_RequireOriginApproval.GetBool()
		if server_structs.IsCacheNS(prefix) {
			requiresApproval = param.Registry_RequireCacheApproval.GetBool()
		}
		if requiresApproval {
			return nil, permissionDeniedError{
				Message: "service " + prefix + " has not been approved by a federation administrator",
			}
		}
		return registration, nil
	}
}

// authorizedNamesForPrefix computes the SANs the certificate may carry: always
// the service slug, plus the DNS hostname the registration authoritatively
// binds to the service. The hostname is derived from the registration prefix
// (/origins/<host> or /caches/<host>) — the registry's own record, not
// something the requester supplies — so a service can only ever be granted a
// name it is registered under. A prefix host that is an IP literal (or empty)
// contributes no DNS SAN; such a service is reached by IP with ServerName=slug.
//
// Note: this covers the common case where a service's web/registration host is
// also its data host. A service whose data endpoint uses a different hostname
// than its registration prefix is reached over that endpoint via ServerName=slug.
func authorizedNamesForPrefix(prefix, slug string) []string {
	names := []string{slug}

	// The hostname is only meaningful for origin/cache service prefixes.
	host := ""
	for _, p := range []string{server_structs.OriginPrefix.String(), server_structs.CachePrefix.String()} {
		if strings.HasPrefix(prefix, p) {
			host = strings.TrimPrefix(prefix, p)
			break
		}
	}
	if host == "" {
		return names
	}
	// Drop a port if present (prefix host may be "example.org:8444").
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Only a real DNS hostname becomes an additional SAN — never an IP literal
	// (IP SANs are not issued) and never a duplicate of the slug.
	if host != "" && host != slug && net.ParseIP(host) == nil {
		names = append(names, host)
	}
	return names
}

// serviceSlugForPrefix returns the unique service-ID slug bound to a prefix.
func serviceSlugForPrefix(prefix string) (string, error) {
	server, err := getServerByPrefix(prefix)
	if err != nil {
		return "", errors.Wrapf(err, "failed to resolve service for prefix %s", prefix)
	}
	if server == nil || server.ID == "" {
		return "", errors.Errorf("no service slug is associated with prefix %s", prefix)
	}
	return server.ID, nil
}

func parseCSRPEM(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("no PEM block found in CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CSR")
	}
	return csr, nil
}

// serveCABundle returns the public federation root certificate.
func serveCABundle(ctx *gin.Context) {
	bundle, err := GetCABundlePEM(nil)
	if err != nil {
		ctx.JSON(http.StatusServiceUnavailable, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "The registry certificate authority is not initialized",
		})
		return
	}
	ctx.Data(http.StatusOK, "application/x-pem-file", []byte(bundle))
}
