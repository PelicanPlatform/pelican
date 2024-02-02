/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

// Common pacakge contains shared structs and methods between different Pelican pacakges.
package common

import (
	"encoding/json"
	"net/url"
)

type (
	TokenIssuer struct {
		BasePaths       []string `json:"base-paths"`
		RestrictedPaths []string `json:"restricted-paths"`
		IssuerUrl       url.URL  `json:"issuer"`
	}

	TokenGen struct {
		Strategy         StrategyType `json:"strategy"`
		VaultServer      string       `json:"vault-server"`
		MaxScopeDepth    uint         `json:"max-scope-depth"`
		CredentialIssuer url.URL      `json:"issuer"`
	}

	Capabilities struct {
		PublicRead   bool
		Read         bool
		Write        bool
		Listing      bool
		FallBackRead bool
	}

	NamespaceAdV2 struct {
		PublicRead bool
		Caps       Capabilities  // Namespace capabilities should be considered independently of the origin’s capabilities.
		Path       string        `json:"path"`
		Generation []TokenGen    `json:"token-generation"`
		Issuer     []TokenIssuer `json:"token-issuer"`
	}

	NamespaceAdV1 struct {
		RequireToken  bool         `json:"requireToken"`
		Path          string       `json:"path"`
		Issuer        url.URL      `json:"url"`
		MaxScopeDepth uint         `json:"maxScopeDepth"`
		Strategy      StrategyType `json:"strategy"`
		BasePath      string       `json:"basePath"`
		VaultServer   string       `json:"vaultServer"`
		DirlistHost   string       `json:"dirlisthost"`
	}

	ServerAd struct {
		Name               string
		AuthURL            url.URL
		URL                url.URL // This is server's XRootD URL for file transfer
		WebURL             url.URL // This is server's Web interface and API
		Type               ServerType
		Latitude           float64
		Longitude          float64
		EnableWrite        bool
		EnableFallbackRead bool // True if reads from the origin are permitted when no cache is available
	}

	ServerType   string
	StrategyType string

	OriginAdvertiseV2 struct {
		Name       string          `json:"name"`
		DataURL    string          `json:"data-url" binding:"required"`
		WebURL     string          `json:"web-url,omitempty"`
		Caps       Capabilities    `json:"capabilities"`
		Namespaces []NamespaceAdV2 `json:"namespaces"`
		Issuer     []TokenIssuer   `json:"token-issuer"`
	}

	OriginAdvertiseV1 struct {
		Name               string          `json:"name"`
		URL                string          `json:"url" binding:"required"` // This is the url for origin's XRootD service and file transfer
		WebURL             string          `json:"web_url,omitempty"`      // This is the url for origin's web engine and APIs
		Namespaces         []NamespaceAdV1 `json:"namespaces"`
		EnableWrite        bool            `json:"enablewrite"`
		EnableFallbackRead bool            `json:"enable-fallback-read"` // True if the origin will allow direct client reads when no caches are available
	}
)

const (
	CacheType  ServerType = "Cache"
	OriginType ServerType = "Origin"
)

const (
	OAuthStrategy StrategyType = "OAuth2"
	VaultStrategy StrategyType = "Vault"
)

func (ad ServerAd) MarshalJSON() ([]byte, error) {
	baseAd := struct {
		Name               string     `json:"name"`
		AuthURL            string     `json:"auth_url"`
		URL                string     `json:"url"`
		WebURL             string     `json:"web_url"`
		Type               ServerType `json:"type"`
		Latitude           float64    `json:"latitude"`
		Longitude          float64    `json:"longitude"`
		EnableWrite        bool       `json:"enable_write"`
		EnableFallbackRead bool       `json:"enable_fallback_read"`
	}{
		Name:               ad.Name,
		AuthURL:            ad.AuthURL.String(),
		URL:                ad.URL.String(),
		WebURL:             ad.WebURL.String(),
		Type:               ad.Type,
		Latitude:           ad.Latitude,
		Longitude:          ad.Longitude,
		EnableWrite:        ad.EnableWrite,
		EnableFallbackRead: ad.EnableFallbackRead,
	}
	return json.Marshal(baseAd)
}
