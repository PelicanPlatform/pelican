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

package issuer

import "time"

// OIDCClientRecord maps to the oidc_clients table.
type OIDCClientRecord struct {
	ID                    string     `gorm:"primaryKey"`
	ClientSecret          string
	RedirectURIs          string
	GrantTypes            string
	ResponseTypes         string
	Scopes                string
	Public                bool
	DynamicallyRegistered bool
	BoundUser             string
	LastUsedAt            *time.Time
	RegistrationIP        string
	CreatedAt             time.Time
}

func (OIDCClientRecord) TableName() string { return "oidc_clients" }

// OIDCTokenSession maps to the oidc_access_tokens, oidc_authorization_codes,
// oidc_pkce_requests, and oidc_openid_sessions tables. It is also used to
// create rows in oidc_refresh_tokens (which adds a first_used_at column
// not present in the other four tables).
type OIDCTokenSession struct {
	Signature       string     `gorm:"primaryKey"`
	RequestID       string
	RequestedAt     time.Time
	ClientID        string
	Scopes          string
	GrantedScopes   string
	GrantedAudience string
	FormData        string
	SessionData     string
	Subject         string
	Active          bool
	ExpiresAt       *time.Time
	CreatedAt       time.Time
}

// OIDCRefreshToken extends OIDCTokenSession with the first_used_at column
// specific to the oidc_refresh_tokens table.
type OIDCRefreshToken struct {
	OIDCTokenSession
	FirstUsedAt *time.Time
}

func (OIDCRefreshToken) TableName() string { return "oidc_refresh_tokens" }

// OIDCDeviceCode maps to the oidc_device_codes table.
type OIDCDeviceCode struct {
	DeviceCode    string     `gorm:"primaryKey"`
	UserCode      string
	RequestID     string
	RequestedAt   time.Time
	ClientID      string
	Scopes        string
	GrantedScopes string
	FormData      string
	SessionData   string
	Subject       string
	Status        string
	ExpiresAt     time.Time
	LastPolledAt  *time.Time
	CreatedAt     time.Time
}

func (OIDCDeviceCode) TableName() string { return "oidc_device_codes" }

// OIDCJWTAssertion maps to the oidc_jwt_assertions table.
type OIDCJWTAssertion struct {
	JTI       string    `gorm:"column:jti;primaryKey"`
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (OIDCJWTAssertion) TableName() string { return "oidc_jwt_assertions" }
