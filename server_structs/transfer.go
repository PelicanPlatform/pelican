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

	"github.com/pelicanplatform/pelican/client_agent/types"
)

// The files in cmd/ that are built into the client binary use the types
// and constants in this file directly. They are parts
// of the transfer server's API. Importing them from the transfer package
// would link the transfer server and everything it imports
// into the client binary.

// TransferErrorResponse is the transfer server's standard error response.
type TransferErrorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

// TransferCredentialResponse is the public view of a transfer credential.
// It omits the credential's secrets.
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

// TransferAuthCodeBootstrapResponse is the transfer server's response
// when it creates an auth-code session.
type TransferAuthCodeBootstrapResponse struct {
	// SessionID is a unique identifier for this bootstrap session.
	SessionID string `json:"session_id"`
	// AuthorizationURL is the URL the user should visit to authorize.
	AuthorizationURL string `json:"authorization_url"`
}

// TransferAuthCodeBootstrapStatus is the transfer server's response
// to a poll of an auth-code session.
type TransferAuthCodeBootstrapStatus struct {
	SessionID    string                      `json:"session_id"`
	Status       string                      `json:"status"` // "pending", "complete", "error"
	CredentialID string                      `json:"credential_id,omitempty"`
	Error        string                      `json:"error,omitempty"`
	Credential   *TransferCredentialResponse `json:"credential,omitempty"`
}

// The OAuth2 grant types that a transfer OAuth2 client can be selected for.
//
// The transfer server's findOAuthClientForGrant matches a stored client
// by comparing these strings against the whitespace-separated grant_types
// recorded on the row. The value that a client is registered with
// must match the value that the lookup asks for exactly. They are constants
// rather than literals at each site because nothing rejects a client
// registered with a near-miss spelling. Such a client never matches,
// and the bootstrap fails later
// with "No OAuth client registered for issuer".
const (
	TransferGrantTypeTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	TransferGrantTypeAuthorizationCode = "authorization_code"
)

// TransferSupportedGrantTypes lists the grants
// that a transfer OAuth2 client may be registered for,
// in order of preference.
var TransferSupportedGrantTypes = []string{TransferGrantTypeAuthorizationCode, TransferGrantTypeTokenExchange}

// TransferOAuthClientCreateRequest is the request body for creating
// a transfer OAuth2 client.
type TransferOAuthClientCreateRequest struct {
	Name         string `json:"name" binding:"required"`
	IssuerURL    string `json:"issuer_url" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	GrantTypes   string `json:"grant_types,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
}

// TransferJobStatus represents the full status of a transfer job.
//
// Progress is the job's live byte and transfer counts. It reuses the shape
// that the client agent publishes for its own jobs, so that a reader
// of either API sees the same field names.
//
// Progress is nil exactly when the transfer server cannot know the counts.
// The JSON then omits it. That happens when the server has evicted a job
// from memory and reconstructs it from its durable record, which carries
// no byte counts. A present Progress with zero bytes means that no bytes
// have moved yet. An absent one means that nobody can say.
type TransferJobStatus struct {
	JobID              string             `json:"job_id"`
	Status             string             `json:"status"`
	CreatedAt          time.Time          `json:"created_at"`
	CompletedAt        *time.Time         `json:"completed_at,omitempty"`
	SourceCredentialID string             `json:"source_credential_id,omitempty"`
	DestCredentialID   string             `json:"dest_credential_id,omitempty"`
	Progress           *types.JobProgress `json:"progress,omitempty"`
	Error              string             `json:"error,omitempty"`
}

// TransferJobListResponse is a paginated list of transfer jobs.
type TransferJobListResponse struct {
	Jobs   []TransferJobStatus `json:"jobs"`
	Total  int                 `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}
