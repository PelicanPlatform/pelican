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
	NamespaceAd struct {
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
		Name               string     `json:"name"`
		AuthURL            url.URL    `json:"auth_url"`
		URL                url.URL    `json:"url"`     // This is server's XRootD URL for file transfer
		WebURL             url.URL    `json:"web_url"` // This is server's Web interface and API
		Type               ServerType `json:"type"`
		Latitude           float64    `json:"latitude"`
		Longitude          float64    `json:"longitude"`
		EnableWrite        bool       `json:"enable_write"`
		EnableFallbackRead bool       `json:"enable_fallback_read"` // True if reads from the origin are permitted when no cache is available
	}

	OriginAdvertise struct {
		Name               string        `json:"name"`
		URL                string        `json:"url"`               // This is the url for origin's XRootD service and file transfer
		WebURL             string        `json:"web_url,omitempty"` // This is the url for origin's web engine and APIs
		Namespaces         []NamespaceAd `json:"namespaces"`
		EnableWrite        bool          `json:"enablewrite"`
		EnableFallbackRead bool          `json:"enable-fallback-read"` // True if the origin will allow direct client reads when no caches are available
	}

	ServerType   string
	StrategyType string
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
