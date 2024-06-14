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

package server_structs

import (
	"encoding/json"
	"net/url"
	"sync"
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

	// Note that the json are kept in uppercase for backward compatibility
	Capabilities struct {
		PublicReads bool `json:"PublicRead"`
		Reads       bool `json:"Read"`
		Writes      bool `json:"Write"`
		Listings    bool `json:"Listing"`
		DirectReads bool `json:"FallBackRead"`
	}

	NamespaceAdV2 struct {
		// TODO: Deprecate this top-level PublicRead field in favor of the Caps.PublicReads field.
		// Should be done ~v7.10 series
		PublicRead   bool
		Caps         Capabilities  // Namespace capabilities should be considered independently of the origin’s capabilities.
		Path         string        `json:"path"`
		Generation   []TokenGen    `json:"token-generation"`
		Issuer       []TokenIssuer `json:"token-issuer"`
		FromTopology bool          `json:"from-topology"`
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
		Name         string       `json:"name"`
		AuthURL      url.URL      `json:"auth_url"`
		BrokerURL    url.URL      `json:"broker_url"` // The URL of the broker service to use for this host.
		URL          url.URL      `json:"url"`        // This is server's XRootD URL for file transfer
		WebURL       url.URL      `json:"web_url"`    // This is server's Web interface and API
		Type         ServerType   `json:"type"`
		Latitude     float64      `json:"latitude"`
		Longitude    float64      `json:"longitude"`
		Caps         Capabilities `json:"capabilities"` // TODO: Get rid of Writes, Listings, DirectReads in favor of Caps.Writes, Caps.Listings, Caps.DirectReads
		Writes       bool         `json:"enable_write"`
		Listings     bool         `json:"enable_listing"`       // True if the origin allows directory listings
		DirectReads  bool         `json:"enable_fallback_read"` // True if reads from the origin are permitted when no cache is available
		FromTopology bool         `json:"from_topology"`
		IOLoad       float64      `json:"io_load"`
	}

	// The struct holding a server's advertisement (including ServerAd and NamespaceAd)
	Advertisement struct {
		sync.RWMutex
		ServerAd
		NamespaceAds []NamespaceAdV2
	}

	ServerType   string
	StrategyType string

	OriginAdvertiseV2 struct {
		// The displayed name of the server.
		// The value is from the Sitename of the server registration in the registry if set, or Xrootd.Sitename if not
		Name string `json:"name"`
		// The namespace prefix to register/look up the server in the registry.
		// The value is /caches/{Xrootd.Sitename} for cache servers and /origins/{Xrootd.Sitename} for the origin servers
		RegistryPrefix string          `json:"registry-prefix"`
		BrokerURL      string          `json:"broker-url,omitempty"`
		DataURL        string          `json:"data-url" binding:"required"`
		WebURL         string          `json:"web-url,omitempty"`
		Caps           Capabilities    `json:"capabilities"`
		Namespaces     []NamespaceAdV2 `json:"namespaces"`
		Issuer         []TokenIssuer   `json:"token-issuer"`
	}

	OriginAdvertiseV1 struct {
		Name        string          `json:"name"`
		URL         string          `json:"url" binding:"required"` // This is the url for origin's XRootD service and file transfer
		WebURL      string          `json:"web_url,omitempty"`      // This is the url for origin's web engine and APIs
		Namespaces  []NamespaceAdV1 `json:"namespaces"`
		Writes      bool            `json:"enablewrite"`
		DirectReads bool            `json:"enable-fallback-read"` // True if the origin will allow direct client reads when no caches are available
	}

	DirectorTestResult struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	}
	GetPrefixByPathRes struct {
		Prefix string `json:"prefix"`
	}

	OpenIdDiscoveryResponse struct {
		Issuer               string   `json:"issuer"`
		JwksUri              string   `json:"jwks_uri"`
		TokenEndpoint        string   `json:"token_endpoint,omitempty"`
		UserInfoEndpoint     string   `json:"userinfo_endpoint,omitempty"`
		RevocationEndpoint   string   `json:"revocation_endpoint,omitempty"`
		GrantTypesSupported  []string `json:"grant_types_supported,omitempty"`
		ScopesSupported      []string `json:"scopes_supported,omitempty"`
		TokenAuthMethods     []string `json:"token_endpoint_auth_methods_supported,omitempty"`
		RegistrationEndpoint string   `json:"registration_endpoint,omitempty"`
		DeviceEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
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

func (ad *ServerAd) MarshalJSON() ([]byte, error) {
	type Alias ServerAd
	return json.Marshal(&struct {
		AuthURL   string `json:"auth_url"`
		BrokerURL string `json:"broker_url"`
		URL       string `json:"url"`
		WebURL    string `json:"web_url"`
		*Alias
	}{
		AuthURL:   ad.AuthURL.String(),
		BrokerURL: ad.BrokerURL.String(),
		URL:       ad.URL.String(),
		WebURL:    ad.WebURL.String(),
		Alias:     (*Alias)(ad),
	})
}

func (ad *Advertisement) SetIOLoad(load float64) {
	ad.Lock()
	defer ad.Unlock()
	ad.IOLoad = load
}

func (ad *Advertisement) GetIOLoad() float64 {
	ad.RLock()
	defer ad.RUnlock()
	return ad.IOLoad
}

func ConvertNamespaceAdsV2ToV1(nsV2 []NamespaceAdV2) []NamespaceAdV1 {
	// Converts a list of V2 namespace ads to a list of V1 namespace ads.
	// This is for backwards compatibility in the case an old version of a client calls
	// out to a newer verion of the director
	nsV1 := []NamespaceAdV1{}

	for _, nsAd := range nsV2 {
		if len(nsAd.Issuer) != 0 {
			for _, iss := range nsAd.Issuer {
				for _, bp := range iss.BasePaths {
					v1Ad := NamespaceAdV1{
						Path:          nsAd.Path,
						RequireToken:  !nsAd.Caps.PublicReads,
						Issuer:        iss.IssuerUrl,
						BasePath:      bp,
						Strategy:      nsAd.Generation[0].Strategy,
						VaultServer:   nsAd.Generation[0].VaultServer,
						MaxScopeDepth: nsAd.Generation[0].MaxScopeDepth,
					}
					nsV1 = append(nsV1, v1Ad)
				}
			}
		} else {
			v1Ad := NamespaceAdV1{
				Path:         nsAd.Path,
				RequireToken: false,
			}
			nsV1 = append(nsV1, v1Ad)
		}
	}

	return nsV1
}

func ConvertNamespaceAdsV1ToV2(nsAdsV1 []NamespaceAdV1, oAd *OriginAdvertiseV1) []NamespaceAdV2 {
	//Convert a list of V1 namespace ads to a list of V2 namespace ads, note that this
	//isn't the most efficient way of doing so (an interative search as opposed to some sort
	//of index or hash based search)

	var wr bool
	var fallback bool
	var credurl url.URL

	if oAd != nil {
		fallback = oAd.DirectReads
		wr = oAd.Writes
	} else {
		fallback = true
		wr = false
	}
	nsAdsV2 := []NamespaceAdV2{}
	for _, nsAd := range nsAdsV1 {
		nsFound := false
		for i := range nsAdsV2 {
			//Namespace exists, so check if issuer already exists
			if nsAdsV2[i].Path == nsAd.Path {
				nsFound = true
				issFound := false
				tokIssuers := nsAdsV2[i].Issuer
				for j := range tokIssuers {
					//Issuer exists, so add the basepaths to the list
					if tokIssuers[j].IssuerUrl == nsAd.Issuer {
						issFound = true
						bps := tokIssuers[j].BasePaths
						bps = append(bps, nsAd.BasePath)
						tokIss := &nsAdsV2[i].Issuer[j]
						(*tokIss).BasePaths = bps
						break
					}
				}
				//Issuer doesn't exist for the URL, so create a new one
				if nsAd.RequireToken {
					if !issFound {
						if oAd != nil {
							urlPtr, err := url.Parse(oAd.URL)
							if err != nil {
								credurl = nsAd.Issuer
							} else {
								credurl = *urlPtr
							}
						} else {
							credurl = nsAd.Issuer
						}

						tIss := TokenIssuer{
							BasePaths:       []string{nsAd.BasePath},
							RestrictedPaths: []string{},
							IssuerUrl:       nsAd.Issuer,
						}
						v2NS := &nsAdsV2[i]
						tis := append(nsAdsV2[i].Issuer, tIss)
						(*v2NS).Issuer = tis
						if len(nsAdsV2[i].Generation) == 0 {
							tGen := TokenGen{
								Strategy:         nsAd.Strategy,
								VaultServer:      nsAd.VaultServer,
								MaxScopeDepth:    nsAd.MaxScopeDepth,
								CredentialIssuer: credurl,
							}
							(*v2NS).Generation = []TokenGen{tGen}
						}
					}
				}
			}
			break
		}
		//Namespace doesn't exist for the Path, so create a new one
		if !nsFound {
			if oAd != nil {
				urlPtr, err := url.Parse(oAd.URL)
				if err != nil {
					credurl = nsAd.Issuer
				} else {
					credurl = *urlPtr
				}
			} else {
				credurl = nsAd.Issuer
			}

			caps := Capabilities{
				PublicReads: !nsAd.RequireToken,
				Reads:       true,
				Writes:      wr,
				Listings:    true,
				DirectReads: fallback,
			}

			newNS := NamespaceAdV2{
				PublicRead: caps.PublicReads,
				Caps:       caps,
				Path:       nsAd.Path,
			}

			if nsAd.RequireToken {
				tGen := []TokenGen{{
					Strategy:         nsAd.Strategy,
					VaultServer:      nsAd.VaultServer,
					MaxScopeDepth:    nsAd.MaxScopeDepth,
					CredentialIssuer: credurl,
				}}
				tIss := []TokenIssuer{{
					BasePaths:       []string{nsAd.BasePath},
					RestrictedPaths: []string{},
					IssuerUrl:       nsAd.Issuer,
				}}

				newNS.Generation = tGen
				newNS.Issuer = tIss
			}

			nsAdsV2 = append(nsAdsV2, newNS)
		}
	}
	return nsAdsV2
}

// Converts a V1 origin advertisement to a V2 origin advertisement
func ConvertOriginAdV1ToV2(oAd1 OriginAdvertiseV1) OriginAdvertiseV2 {

	nsAdsV2 := ConvertNamespaceAdsV1ToV2(oAd1.Namespaces, &oAd1)
	tokIssuers := []TokenIssuer{}

	for _, v2Ad := range nsAdsV2 {
		tokIssuers = append(tokIssuers, v2Ad.Issuer...)
	}

	//Origin Capabilities may be different from Namespace Capabilities, but since the original
	//origin didn't contain capabilities, these are currently the defaults - we might want to potentially
	//change this in the future
	caps := Capabilities{
		PublicReads: true,
		Reads:       true,
		Writes:      oAd1.Writes,
		Listings:    true,
		DirectReads: oAd1.DirectReads,
	}

	oAd2 := OriginAdvertiseV2{
		Name:       oAd1.Name,
		DataURL:    oAd1.URL,
		WebURL:     oAd1.WebURL,
		Caps:       caps,
		Namespaces: nsAdsV2,
		Issuer:     tokIssuers,
	}
	return oAd2
}

func ServerAdsToServerNameURL(ads []ServerAd) (output string) {
	for _, ad := range ads {
		output += ad.Name + ":" + ad.URL.String() + "\n"
	}
	return
}
