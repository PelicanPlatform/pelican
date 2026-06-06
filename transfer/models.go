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

package transfer

import (
	"time"
)

// TransferCredential represents a stored credential in the database.
type TransferCredential struct {
	ID                    string     `gorm:"primaryKey;column:id" json:"id"`
	UserID                string     `gorm:"column:user_id;not null" json:"-"`
	Name                  string     `gorm:"column:name;not null" json:"name"`
	CredentialType        string     `gorm:"column:credential_type;not null;default:'bearer'" json:"credential_type"`
	EncryptedAccessToken  string     `gorm:"column:encrypted_access_token;not null;default:''" json:"-"`
	EncryptedRefreshToken *string    `gorm:"column:encrypted_refresh_token" json:"-"`
	Scopes                string     `gorm:"column:scopes;not null;default:''" json:"scopes,omitempty"`
	TokenIssuer           string     `gorm:"column:token_issuer;not null;default:''" json:"token_issuer,omitempty"`
	TokenExpiry           *time.Time `gorm:"column:token_expiry" json:"token_expiry,omitempty"`
	LastUsedAt            *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
	CreatedAt             time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt             time.Time  `gorm:"column:updated_at" json:"updated_at"`
}

// TableName overrides the default GORM table name.
func (TransferCredential) TableName() string {
	return "transfer_credentials"
}

// TransferOAuthClient represents a stored OAuth2 client registration.
type TransferOAuthClient struct {
	ID                    string    `gorm:"primaryKey;column:id" json:"id"`
	UserID                string    `gorm:"column:user_id;not null" json:"-"`
	Name                  string    `gorm:"column:name;not null" json:"name"`
	IssuerURL             string    `gorm:"column:issuer_url;not null" json:"issuer_url"`
	EncryptedClientID     string    `gorm:"column:encrypted_client_id;not null;default:''" json:"-"`
	EncryptedClientSecret string    `gorm:"column:encrypted_client_secret;not null;default:''" json:"-"`
	GrantTypes            string    `gorm:"column:grant_types;not null;default:''" json:"grant_types,omitempty"`
	Scopes                string    `gorm:"column:scopes;not null;default:''" json:"scopes,omitempty"`
	CreatedAt             time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt             time.Time `gorm:"column:updated_at" json:"updated_at"`
}

// TableName overrides the default GORM table name.
func (TransferOAuthClient) TableName() string {
	return "transfer_oauth_clients"
}

// TransferJob represents a transfer job record in the database.
// Status is derived from the joined client_agent job (via AgentJobID)
// rather than stored redundantly.
type TransferJob struct {
	ID                 string     `gorm:"primaryKey;column:id" json:"id"`
	UserID             string     `gorm:"column:user_id;not null" json:"-"`
	AgentJobID         *string    `gorm:"column:agent_job_id" json:"-"`
	SourceCredentialID *string    `gorm:"column:source_credential_id" json:"source_credential_id,omitempty"`
	DestCredentialID   *string    `gorm:"column:dest_credential_id" json:"dest_credential_id,omitempty"`
	RequestBody        string     `gorm:"column:request_body;not null;default:''" json:"-"`
	Error              string     `gorm:"column:error;not null;default:''" json:"error,omitempty"`
	CreatedAt          time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt          time.Time  `gorm:"column:updated_at" json:"updated_at"`
	CompletedAt        *time.Time `gorm:"column:completed_at" json:"completed_at,omitempty"`
}

// TableName overrides the default GORM table name.
func (TransferJob) TableName() string {
	return "transfer_jobs"
}

// API request/response types

// CredentialCreateRequest is the request body for creating a credential.
type CredentialCreateRequest struct {
	Name        string `json:"name" binding:"required"`
	AccessToken string `json:"access_token" binding:"required"`
	TokenIssuer string `json:"token_issuer,omitempty"`
}

// CredentialResponse is the public view of a credential (no secrets).
type CredentialResponse struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CredentialType string     `json:"credential_type"`
	TokenIssuer    string     `json:"token_issuer,omitempty"`
	TokenExpiry    *time.Time `json:"token_expiry,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// OAuthClientCreateRequest is the request body for creating an OAuth2 client.
type OAuthClientCreateRequest struct {
	Name         string `json:"name" binding:"required"`
	IssuerURL    string `json:"issuer_url" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	GrantTypes   string `json:"grant_types,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
}

// OAuthClientResponse is the public view of an OAuth2 client (no secrets).
type OAuthClientResponse struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	IssuerURL  string    `json:"issuer_url"`
	GrantTypes string    `json:"grant_types,omitempty"`
	Scopes     string    `json:"scopes,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TransferJobCreateRequest is the request body for submitting a transfer job.
type TransferJobCreateRequest struct {
	Transfers          []TransferItem `json:"transfers" binding:"required,min=1,dive"`
	SourceCredentialID string         `json:"source_credential_id,omitempty"`
	DestCredentialID   string         `json:"dest_credential_id,omitempty"`
	Options            TransferOpts   `json:"options"`
}

// TransferItem represents a single transfer within a job.
type TransferItem struct {
	Operation   string `json:"operation" binding:"required,oneof=get put copy prestage"`
	Source      string `json:"source" binding:"required"`
	Destination string `json:"destination"`
	Recursive   bool   `json:"recursive"`
}

// TransferOpts contains transfer options.
type TransferOpts struct {
	Caches     []string `json:"caches,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	PackOption string   `json:"pack_option,omitempty"`
}

// TransferJobResponse is the response for a submitted transfer job.
type TransferJobResponse struct {
	JobID     string         `json:"job_id"`
	Status    string         `json:"status"`
	CreatedAt time.Time      `json:"created_at"`
	Transfers []TransferItem `json:"transfers"`
}

// TransferJobStatus represents the full status of a transfer job.
type TransferJobStatus struct {
	JobID              string     `json:"job_id"`
	Status             string     `json:"status"`
	CreatedAt          time.Time  `json:"created_at"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	SourceCredentialID string     `json:"source_credential_id,omitempty"`
	DestCredentialID   string     `json:"dest_credential_id,omitempty"`
	Error              string     `json:"error,omitempty"`
}

// TransferJobListResponse is a paginated list of transfer jobs.
type TransferJobListResponse struct {
	Jobs   []TransferJobStatus `json:"jobs"`
	Total  int                 `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
}

// ErrorResponse is a standard error response.
type ErrorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

// ownerIdentity represents the authenticated user, resolved to a users table ID.
type ownerIdentity struct {
	UserID string
}
