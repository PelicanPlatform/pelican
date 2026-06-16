//go:build client || server

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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	pelican_oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/transfer"
)

// normalizeServerURL strips any trailing slashes from a server URL.
func normalizeServerURL(serverURL string) string {
	return strings.TrimRight(serverURL, "/")
}

// authenticateWithTransferServer uses DCRP + device code flow to obtain a
// bearer token for the transfer server.  It looks up (or creates) a
// TransferServerEntry in the credential file.
//
// Returns the access token and a pointer to the TransferServerEntry (which may
// have been updated with a new OAuth client registration).
func authenticateWithTransferServer(ctx context.Context, serverURL string) (string, *config.TransferServerEntry, error) {
	serverURL = normalizeServerURL(serverURL)

	// Load existing credential file
	osdfConfigVal, err := config.GetCredentialConfigContents()
	var osdfConfig *config.CredentialConfig
	if err != nil {
		osdfConfig = &config.CredentialConfig{}
	} else {
		osdfConfig = &osdfConfigVal
	}

	// Look for an existing entry for this server
	fc, tsIdx := osdfConfig.FindTransferServer(param.Federation_DiscoveryUrl.GetString(), serverURL)

	var entry *config.TransferServerEntry
	if tsIdx >= 0 {
		entry = &fc.TransferServers[tsIdx]
	}

	// Discover the server's local issuer (which mints pelican.transfer tokens)
	// from the transfer ping endpoint, then fetch its OIDC metadata. Older
	// servers that don't advertise an issuer fall back to the server URL.
	issuerURL := discoverTransferIssuer(ctx, serverURL)
	issuerMeta, err := config.GetIssuerMetadata(issuerURL)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to get transfer server's issuer metadata")
	}

	needRegistration := entry == nil || entry.ClientID == "" || entry.ClientSecret == ""

	if needRegistration {
		if issuerMeta.RegistrationURL == "" {
			return "", nil, errors.New("transfer server does not support dynamic client registration")
		}

		drcp := pelican_oauth2.DCRPConfig{
			ClientRegistrationEndpointURL: issuerMeta.RegistrationURL,
			Transport:                     config.GetTransport(),
			Metadata: pelican_oauth2.Metadata{
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Pelican Transfer CLI",
				Scopes:                  []string{"offline_access", "pelican.transfer"},
			},
		}

		resp, err := drcp.Register()
		if err != nil {
			return "", nil, errors.Wrap(err, "DCRP registration with transfer server failed")
		}

		if entry == nil {
			fc.TransferServers = append(fc.TransferServers, config.TransferServerEntry{
				ServerURL: serverURL,
				ClientRegistration: config.ClientRegistration{
					ClientID:     resp.ClientID,
					ClientSecret: resp.ClientSecret,
					ClientScopes: []string{"offline_access", "pelican.transfer"},
				},
			})
			entry = &fc.TransferServers[len(fc.TransferServers)-1]
		} else {
			entry.ClientID = resp.ClientID
			entry.ClientSecret = resp.ClientSecret
		}

		if err := config.SaveConfigContents(osdfConfig); err != nil {
			log.Warningln("Failed to save transfer server registration:", err)
		}
	}

	// Check for a cached token with at least a minute of remaining validity
	for _, cached := range entry.Tokens {
		if cached.AccessToken != "" && time.Now().Add(time.Minute).Before(time.Unix(cached.Expiration, 0)) {
			log.Debugln("Returning cached transfer server token")
			return cached.AccessToken, entry, nil
		}
	}

	// Now use device code flow to get a user token
	oauthCfg := pelican_oauth2.Config{
		ClientID:     entry.ClientID,
		ClientSecret: entry.ClientSecret,
		Endpoint: pelican_oauth2.Endpoint{
			DeviceAuthURL: issuerMeta.DeviceAuthURL,
			TokenURL:      issuerMeta.TokenURL,
		},
		Scopes: []string{"pelican.transfer"},
	}

	// Inject the Pelican transport (with TLS settings) into the context so
	// AuthDevice and Poll use it instead of http.DefaultClient.
	httpClient := &http.Client{Transport: config.GetTransport()}
	ctx = context.WithValue(ctx, pelican_oauth2.HTTPClient, httpClient)

	da, err := oauthCfg.AuthDevice(ctx)
	if errors.Is(err, pelican_oauth2.ErrUnknownClient) {
		// Client was garbage-collected; re-register
		log.Info("Transfer server does not recognize our client; re-registering")
		drcp := pelican_oauth2.DCRPConfig{
			ClientRegistrationEndpointURL: issuerMeta.RegistrationURL,
			Transport:                     config.GetTransport(),
			Metadata: pelican_oauth2.Metadata{
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Pelican Transfer CLI",
				Scopes:                  []string{"offline_access", "pelican.transfer"},
			},
		}
		resp, regErr := drcp.Register()
		if regErr != nil {
			return "", nil, errors.Wrap(regErr, "re-registration with transfer server failed")
		}
		entry.ClientID = resp.ClientID
		entry.ClientSecret = resp.ClientSecret
		oauthCfg.ClientID = resp.ClientID
		oauthCfg.ClientSecret = resp.ClientSecret
		if err := config.SaveConfigContents(osdfConfig); err != nil {
			log.Warningln("Failed to save updated transfer server registration:", err)
		}

		da, err = oauthCfg.AuthDevice(ctx)
	}
	if err != nil {
		return "", nil, errors.Wrap(err, "device authorization request failed")
	}

	fmt.Printf("To authenticate with the transfer server, visit:\n  %s\nand enter code: %s\n",
		da.VerificationURI, da.UserCode)
	if da.VerificationURIComplete != "" {
		fmt.Printf("Or visit: %s\n", da.VerificationURIComplete)
	}

	token, err := oauthCfg.Poll(ctx, da)
	if err != nil {
		return "", nil, errors.Wrap(err, "device code polling failed")
	}

	// Cache the token for future reuse
	newToken := config.TokenEntry{
		AccessToken: token.AccessToken,
		Expiration:  token.Expiry.Unix(),
	}
	entry.Tokens = []config.TokenEntry{newToken}

	if err := config.SaveConfigContents(osdfConfig); err != nil {
		log.Warningln("Failed to save credential file:", err)
	}

	return token.AccessToken, entry, nil
}

// discoverTransferIssuer asks the transfer server's ping endpoint for the URL
// of the local issuer that mints pelican.transfer tokens. It falls back to the
// server URL itself for older servers that do not advertise an issuer.
func discoverTransferIssuer(ctx context.Context, serverURL string) string {
	client := &http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		normalizeServerURL(serverURL)+"/api/v1.0/transfer/ping", nil)
	if err != nil {
		return serverURL
	}
	resp, err := client.Do(req)
	if err != nil {
		return serverURL
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return serverURL
	}
	body, _ := io.ReadAll(resp.Body)
	var ping struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &ping); err != nil || ping.Issuer == "" {
		return serverURL
	}
	return ping.Issuer
}

// queryAuthMethods asks the transfer server what credential-bootstrap flows
// it supports for the given issuer.
func queryAuthMethods(ctx context.Context, serverURL, bearerToken, issuerURL string) ([]string, error) {
	transport := config.GetTransport()
	client := &http.Client{Transport: transport}

	reqURL, err := url.Parse(normalizeServerURL(serverURL) + "/api/v1.0/transfer/auth-methods")
	if err != nil {
		return nil, errors.Wrap(err, "failed to build auth-methods URL")
	}
	q := reqURL.Query()
	q.Set("issuer", issuerURL)
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query auth methods")
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth-methods query returned %d: %s", resp.StatusCode, string(body))
	}

	var result transfer.AuthMethodsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.Wrap(err, "failed to parse auth methods response")
	}

	return result.Methods, nil
}

// bootstrapCredentialViaTokenExchange bootstraps a credential on the transfer
// server using the token-exchange flow: the CLI presents an existing token
// (obtained via device code from the issuer) and the server exchanges it.
func bootstrapCredentialViaTokenExchange(ctx context.Context, serverURL, bearerToken, issuerURL, credName, subjectToken string) (string, error) {
	transport := config.GetTransport()
	client := &http.Client{Transport: transport}

	reqBody := map[string]string{
		"subject_token": subjectToken,
		"issuer_url":    issuerURL,
		"name":          credName,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	apiURL := normalizeServerURL(serverURL) + "/api/v1.0/transfer/credentials/bootstrap/token-exchange"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "token-exchange bootstrap request failed")
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("token-exchange bootstrap returned %d: %s", resp.StatusCode, string(body))
	}

	var cred transfer.CredentialResponse
	if err := json.Unmarshal(body, &cred); err != nil {
		return "", errors.Wrap(err, "failed to parse credential response")
	}

	return cred.ID, nil
}

// bootstrapCredentialViaAuthCode bootstraps a credential using the
// authorization code flow: the server returns a URL, the user visits it, and
// the CLI polls for completion.
func bootstrapCredentialViaAuthCode(ctx context.Context, serverURL, bearerToken, issuerURL, credName string, scopes []string) (string, error) {
	transport := config.GetTransport()
	client := &http.Client{Transport: transport}

	// Start the auth code session. Request the storage scopes the credential
	// needs (e.g. storage.read for the source); without them the issuer only
	// grants offline_access and the data movement is unauthorized.
	reqBody := map[string]string{
		"issuer_url": issuerURL,
		"name":       credName,
	}
	if len(scopes) > 0 {
		reqBody["scopes"] = strings.Join(scopes, " ")
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	apiURL := normalizeServerURL(serverURL) + "/api/v1.0/transfer/credentials/bootstrap/authcode"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "auth-code bootstrap request failed")
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth-code bootstrap returned %d: %s", resp.StatusCode, string(body))
	}

	var authCodeResp transfer.AuthCodeBootstrapResponse
	if err := json.Unmarshal(body, &authCodeResp); err != nil {
		return "", errors.Wrap(err, "failed to parse auth-code bootstrap response")
	}

	fmt.Printf("To authorize credential access, visit:\n  %s\n", authCodeResp.AuthorizationURL)

	// Poll for completion
	pollURL := normalizeServerURL(serverURL) + "/api/v1.0/transfer/credentials/bootstrap/authcode/" + authCodeResp.SessionID
	pollInterval := 5 * time.Second
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}

		pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if err != nil {
			return "", err
		}
		pollReq.Header.Set("Authorization", "Bearer "+bearerToken)

		pollResp, err := client.Do(pollReq)
		if err != nil {
			log.Debugf("Poll request failed: %v", err)
			continue
		}

		pollBody, _ := io.ReadAll(pollResp.Body)
		pollResp.Body.Close()

		if pollResp.StatusCode == http.StatusTooManyRequests {
			pollInterval += time.Second
			log.Debugf("Server returned 429; increasing poll interval to %v", pollInterval)
			continue
		}
		if pollResp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("poll returned %d: %s", pollResp.StatusCode, string(pollBody))
		}

		var status transfer.AuthCodeBootstrapStatus
		if err := json.Unmarshal(pollBody, &status); err != nil {
			return "", errors.Wrap(err, "failed to parse poll response")
		}

		switch status.Status {
		case "complete":
			fmt.Println("Credential created successfully.")
			return status.CredentialID, nil
		case "error":
			return "", fmt.Errorf("authorization code flow failed: %s", status.Error)
		case "slow_down":
			pollInterval += time.Second
			log.Debugf("Server requested slow down; increasing poll interval to %v", pollInterval)
		case "pending":
			// keep polling
		default:
			return "", fmt.Errorf("unexpected session status: %s", status.Status)
		}
	}
}

// bootstrapCredential tries to bootstrap a credential on the transfer server
// for the given issuer. It tries the available methods in preference order:
// authorization_code > token_exchange.  The scopes parameter specifies which
// storage scopes the credential should be bootstrapped with (e.g.
// "storage.read:/", "storage.modify:/").
func bootstrapCredential(ctx context.Context, serverURL, bearerToken, issuerURL, credName string, scopes []string) (string, error) {
	methods, err := queryAuthMethods(ctx, serverURL, bearerToken, issuerURL)
	if err != nil {
		return "", errors.Wrap(err, "failed to query auth methods")
	}

	log.Debugf("Transfer server supports methods for %s: %v", issuerURL, methods)

	// Try authorization_code first (preferred — the server handles the full
	// OAuth flow so the user just clicks a link)
	if slices.Contains(methods, "authorization_code") {
		credID, err := bootstrapCredentialViaAuthCode(ctx, serverURL, bearerToken, issuerURL, credName, scopes)
		if err == nil {
			return credID, nil
		}
		log.Warningf("Auth code bootstrap failed, trying fallback: %v", err)
	}

	// Try token_exchange (the CLI obtains a token from the issuer directly
	// via device code flow, then sends it to the transfer server)
	if slices.Contains(methods, "token_exchange") {
		// First get a token from the issuer using device code
		subjectToken, err := acquireTokenFromIssuer(ctx, issuerURL, scopes)
		if err != nil {
			return "", errors.Wrap(err, "failed to acquire token from issuer for token exchange")
		}
		credID, err := bootstrapCredentialViaTokenExchange(ctx, serverURL, bearerToken, issuerURL, credName, subjectToken)
		if err != nil {
			return "", errors.Wrap(err, "token exchange bootstrap failed")
		}
		return credID, nil
	}

	return "", fmt.Errorf("no supported credential bootstrap method available for issuer %s (available: %v)", issuerURL, methods)
}

// acquireTokenFromIssuer uses DCRP + device code flow to get a token from an
// external issuer (not the transfer server itself).  The storageScopes
// parameter specifies storage-level scopes to request (e.g. "storage.read:/");
// protocol scopes like "offline_access" and "wlcg" are added automatically.
//
// The DCRP client registration and resulting tokens are cached in the local
// credential file, keyed by the issuer URL.
func acquireTokenFromIssuer(ctx context.Context, issuerURL string, storageScopes []string) (string, error) {
	issuerMeta, err := config.GetIssuerMetadata(issuerURL)
	if err != nil {
		return "", errors.Wrap(err, "failed to get issuer metadata")
	}

	// Build the full scope list: protocol scopes + requested storage scopes.
	allScopes := append([]string{"offline_access", "wlcg"}, storageScopes...)

	// Check the credential file for a cached client registration and token.
	osdfConfigVal, err := config.GetCredentialConfigContents()
	var osdfConfig *config.CredentialConfig
	if err != nil {
		osdfConfig = &config.CredentialConfig{}
	} else {
		osdfConfig = &osdfConfigVal
	}

	discoveryURL := param.Federation_DiscoveryUrl.GetString()
	fc, prefixIdx := osdfConfig.FindOauthClient(discoveryURL, issuerURL)

	var entry *config.PrefixEntry
	if prefixIdx >= 0 {
		entry = &fc.OauthClient[prefixIdx]

		// Check for a cached token with remaining validity.
		for _, cached := range entry.Tokens {
			if cached.AccessToken != "" && time.Now().Add(time.Minute).Before(time.Unix(cached.Expiration, 0)) {
				log.Debugf("Returning cached token for issuer %s", issuerURL)
				return cached.AccessToken, nil
			}
		}
	}

	needRegistration := entry == nil || entry.ClientID == "" || entry.ClientSecret == ""

	if needRegistration {
		if issuerMeta.RegistrationURL == "" {
			return "", fmt.Errorf("issuer %s does not support dynamic client registration", issuerURL)
		}

		drcp := pelican_oauth2.DCRPConfig{
			ClientRegistrationEndpointURL: issuerMeta.RegistrationURL,
			Transport:                     config.GetTransport(),
			Metadata: pelican_oauth2.Metadata{
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Pelican Transfer CLI",
				Scopes:                  allScopes,
			},
		}

		resp, err := drcp.Register()
		if err != nil {
			return "", errors.Wrap(err, "DCRP registration with issuer failed")
		}

		if entry == nil {
			fc.OauthClient = append(fc.OauthClient, config.PrefixEntry{
				Prefix: issuerURL,
				ClientRegistration: config.ClientRegistration{
					ClientID:     resp.ClientID,
					ClientSecret: resp.ClientSecret,
					ClientScopes: allScopes,
				},
			})
			entry = &fc.OauthClient[len(fc.OauthClient)-1]
		} else {
			entry.ClientID = resp.ClientID
			entry.ClientSecret = resp.ClientSecret
		}

		if err := config.SaveConfigContents(osdfConfig); err != nil {
			log.Warningln("Failed to save issuer client registration:", err)
		}
	}

	oauthCfg := pelican_oauth2.Config{
		ClientID:     entry.ClientID,
		ClientSecret: entry.ClientSecret,
		Endpoint: pelican_oauth2.Endpoint{
			DeviceAuthURL: issuerMeta.DeviceAuthURL,
			TokenURL:      issuerMeta.TokenURL,
		},
		Scopes: allScopes,
	}

	// Inject the Pelican transport (with TLS settings) into the context so
	// AuthDevice and Poll use it instead of http.DefaultClient.
	httpClient := &http.Client{Transport: config.GetTransport()}
	ctx = context.WithValue(ctx, pelican_oauth2.HTTPClient, httpClient)

	da, err := oauthCfg.AuthDevice(ctx)
	if err != nil {
		return "", errors.Wrap(err, "device authorization request failed")
	}

	fmt.Printf("To authenticate with the issuer (%s), visit:\n  %s\nand enter code: %s\n",
		issuerURL, da.VerificationURI, da.UserCode)
	if da.VerificationURIComplete != "" {
		fmt.Printf("Or visit: %s\n", da.VerificationURIComplete)
	}

	token, err := oauthCfg.Poll(ctx, da)
	if err != nil {
		return "", errors.Wrap(err, "device code polling failed")
	}

	// Cache the token for future reuse.
	entry.Tokens = []config.TokenEntry{{
		AccessToken: token.AccessToken,
		Expiration:  token.Expiry.Unix(),
	}}
	if err := config.SaveConfigContents(osdfConfig); err != nil {
		log.Warningln("Failed to save cached issuer token:", err)
	}

	return token.AccessToken, nil
}

// lookupOrBootstrapCredentials resolves credential IDs for a transfer server
// submission. If credential IDs are already provided, they are used directly.
// Otherwise, it determines the federation issuer for the source/destination
// paths, checks the local credential file for a cached credential for that
// issuer, and if none is found, bootstraps a new credential.
//
// serverToken is a pre-resolved bearer token for authenticating with the
// transfer server; if empty the function will bootstrap authentication via
// DCRP + device code flow.
//
// Returns (srcCredID, dstCredID, bearerToken, error).
func lookupOrBootstrapCredentials(ctx context.Context, serverURL, serverToken, srcCredID, dstCredID string, sources []string, dest string) (string, string, string, error) {
	// If both credential IDs were provided, use them directly
	if srcCredID != "" && dstCredID != "" {
		return srcCredID, dstCredID, serverToken, nil
	}

	serverURL = normalizeServerURL(serverURL)

	// Determine the federation namespace info (issuer + scope metadata)
	// for any paths we still need credentials for.
	var srcNS, dstNS *token_scopes.NamespaceInfo
	if srcCredID == "" && len(sources) > 0 {
		srcNS = resolveNamespaceInfo(ctx, sources[0])
	}
	if dstCredID == "" {
		dstNS = resolveNamespaceInfo(ctx, dest)
	}

	// Load credential file and check for cached credential IDs by issuer
	osdfConfigVal, err := config.GetCredentialConfigContents()
	var osdfConfig *config.CredentialConfig
	if err != nil {
		osdfConfig = &config.CredentialConfig{}
	} else {
		osdfConfig = &osdfConfigVal
	}

	fc, tsIdx := osdfConfig.FindTransferServer(param.Federation_DiscoveryUrl.GetString(), serverURL)

	var entry *config.TransferServerEntry
	if tsIdx >= 0 {
		entry = &fc.TransferServers[tsIdx]
	}

	// Compute path-specific scopes from the director response.
	var readScopes, writeScopes []string
	var srcIssuer, dstIssuer string

	if srcNS != nil {
		srcIssuer = srcNS.IssuerURL
		srcPath := token_scopes.ExtractObjectPath(sources[0])
		readScopes = srcNS.ComputeReadScopes(srcPath)
	}
	if dstNS != nil {
		dstIssuer = dstNS.IssuerURL
		dstPath := token_scopes.ExtractObjectPath(dest)
		writeScopes = dstNS.ComputeWriteScopes(dstPath)
	}

	// Look up cached credentials by issuer and required scopes
	if entry != nil {
		if srcCredID == "" && srcIssuer != "" && len(readScopes) > 0 {
			if saved := entry.FindCredential(srcIssuer, readScopes); saved != "" {
				srcCredID = saved
				log.Debugf("Using saved credential %s for issuer %s (source, read)", srcCredID, srcIssuer)
			}
		}
		if dstCredID == "" && dstIssuer != "" && len(writeScopes) > 0 {
			if saved := entry.FindCredential(dstIssuer, writeScopes); saved != "" {
				dstCredID = saved
				log.Debugf("Using saved credential %s for issuer %s (destination, write)", dstCredID, dstIssuer)
			}
		}
	}

	// If we now have both, use them
	if srcCredID != "" && dstCredID != "" {
		return srcCredID, dstCredID, serverToken, nil
	}

	// We need to bootstrap. First, authenticate with the transfer server.
	bearerToken := serverToken
	if bearerToken == "" {
		bearerToken, entry, err = authenticateWithTransferServer(ctx, serverURL)
		if err != nil {
			return "", "", "", errors.Wrap(err, "failed to authenticate with transfer server")
		}
	}

	// Bootstrap missing credentials by issuer
	if srcCredID == "" && srcIssuer != "" && len(readScopes) > 0 {
		log.Infof("Bootstrapping credential for issuer %s (read, scopes=%v)", srcIssuer, readScopes)
		credID, err := bootstrapCredential(ctx, serverURL, bearerToken, srcIssuer, "auto", readScopes)
		if err != nil {
			return "", "", "", errors.Wrap(err, "failed to bootstrap source credential")
		}
		srcCredID = credID
		log.Infof("Credential created for issuer %s: %s (read)", srcIssuer, srcCredID)
		saveCredentialMapping(serverURL, srcIssuer, credID, readScopes)
	}

	if dstCredID == "" && dstIssuer != "" && len(writeScopes) > 0 {
		// If the destination shares an issuer with the source, check whether
		// the source credential already covers the write scopes.
		if dstIssuer == srcIssuer && srcCredID != "" {
			if entry != nil {
				if cid := entry.FindCredential(dstIssuer, writeScopes); cid == srcCredID {
					dstCredID = srcCredID
					log.Debugf("Reusing credential %s for destination (same issuer %s, write scopes present)", dstCredID, dstIssuer)
				}
			}
		}
		if dstCredID == "" {
			log.Infof("Bootstrapping credential for issuer %s (write, scopes=%v)", dstIssuer, writeScopes)
			credID, err := bootstrapCredential(ctx, serverURL, bearerToken, dstIssuer, "auto", writeScopes)
			if err != nil {
				return "", "", "", errors.Wrap(err, "failed to bootstrap destination credential")
			}
			dstCredID = credID
			log.Infof("Credential created for issuer %s: %s (write)", dstIssuer, dstCredID)
			saveCredentialMapping(serverURL, dstIssuer, credID, writeScopes)
		}
	}

	return srcCredID, dstCredID, bearerToken, nil
}

// readTokenFile reads a bearer token from the given file path.
// Returns an empty string if tokenFile is empty.
func readTokenFile(tokenFile string) (string, error) {
	if tokenFile == "" {
		return "", nil
	}
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", errors.Wrap(err, "failed to read token file")
	}
	return strings.TrimSpace(string(data)), nil
}

// resolveNamespaceInfo queries the director to determine the token issuer
// and scope metadata for a particular namespace path.  If the URL uses a
// Pelican scheme (pelican://, osdf://, etc.) it performs federation discovery,
// queries the director, and returns the issuer URL, base path, namespace, and
// max scope depth.  For non-federation URLs it returns nil.
func resolveNamespaceInfo(ctx context.Context, rawURL string) *token_scopes.NamespaceInfo {
	// Quick check: only attempt discovery for federation-scheme URLs.
	parsed, err := url.Parse(rawURL)
	if err != nil || !pelican_url.IsPelicanScheme(parsed.Scheme) {
		return nil
	}

	pUrl, err := client.ParseRemoteAsPUrl(ctx, rawURL)
	if err != nil {
		log.Debugf("Failed to parse %s as a Pelican URL: %v", rawURL, err)
		return nil
	}

	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, http.MethodGet, "")
	if err != nil {
		log.Debugf("Failed to query director for %s: %v", rawURL, err)
		return nil
	}

	if len(dirResp.XPelTokGenHdr.Issuers) == 0 || dirResp.XPelTokGenHdr.Issuers[0] == nil {
		log.Debugf("No issuer found in director response for %s", rawURL)
		return nil
	}

	info := &token_scopes.NamespaceInfo{
		IssuerURL:     dirResp.XPelTokGenHdr.Issuers[0].String(),
		Namespace:     dirResp.XPelNsHdr.Namespace,
		MaxScopeDepth: dirResp.XPelTokGenHdr.MaxScopeDepth,
	}
	if len(dirResp.XPelTokGenHdr.BasePaths) > 0 {
		info.BasePath = dirResp.XPelTokGenHdr.BasePaths[0]
	}
	log.Debugf("Resolved namespace info for %s: issuer=%s basePath=%s namespace=%s maxScopeDepth=%d",
		rawURL, info.IssuerURL, info.BasePath, info.Namespace, info.MaxScopeDepth)
	return info
}

// saveCredentialMapping saves a credential entry (with scopes) for a given
// issuer on a transfer server to the local credential file.
func saveCredentialMapping(serverURL, issuerURL, credID string, scopes []string) {
	serverURL = normalizeServerURL(serverURL)

	osdfConfigVal, err := config.GetCredentialConfigContents()
	var osdfConfig *config.CredentialConfig
	if err != nil {
		osdfConfig = &config.CredentialConfig{}
	} else {
		osdfConfig = &osdfConfigVal
	}

	newEntry := config.CredentialEntry{
		IssuerURL:    issuerURL,
		CredentialID: credID,
		Scopes:       scopes,
	}

	fc, tsIdx := osdfConfig.FindTransferServer(param.Federation_DiscoveryUrl.GetString(), serverURL)

	if tsIdx >= 0 {
		fc.TransferServers[tsIdx].Credentials = append(
			fc.TransferServers[tsIdx].Credentials, newEntry)
	} else {
		fc.TransferServers = append(fc.TransferServers, config.TransferServerEntry{
			ServerURL:   serverURL,
			Credentials: []config.CredentialEntry{newEntry},
		})
	}

	if err := config.SaveConfigContents(osdfConfig); err != nil {
		log.Warningln("Failed to save credential mapping:", err)
	}
}
