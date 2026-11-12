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

package server_structs

import (
	"time"
)

// The transfer server's API types that the commands in cmd/transfer_*.go
// use directly. They live here, rather than in the transfer package,
// so that the client binary can use them without linking in the transfer
// server and everything it imports.

// TransferErrorResponse is the transfer server's standard error response.
type TransferErrorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

// TransferCredentialResponse is the public view of a transfer credential
// (no secrets).
type TransferCredentialResponse struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CredentialType string     `json:"credential_type"`
	TokenIssuer    string     `json:"token_issuer,omitempty"`
	TokenExpiry    *time.Time `json:"token_expiry,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// TransferAuthMethodsResponse describes what credential acquisition flows
// the transfer server supports for a given issuer.
type TransferAuthMethodsResponse struct {
	Issuer  string   `json:"issuer"`
	Methods []string `json:"methods"`
}

// TransferAuthCodeBootstrapResponse is returned when
// a new auth-code session is created.
type TransferAuthCodeBootstrapResponse struct {
	// SessionID is a unique identifier for this bootstrap session.
	SessionID string `json:"session_id"`
	// AuthorizationURL is the URL the user should visit to authorize.
	AuthorizationURL string `json:"authorization_url"`
}

// TransferAuthCodeBootstrapStatus is returned when polling for
// an auth-code session.
type TransferAuthCodeBootstrapStatus struct {
	SessionID    string                      `json:"session_id"`
	Status       string                      `json:"status"` // "pending", "complete", "error"
	CredentialID string                      `json:"credential_id,omitempty"`
	Error        string                      `json:"error,omitempty"`
	Credential   *TransferCredentialResponse `json:"credential,omitempty"`
}
