/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/version"
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

	// Downtime represents a server downtime event
	Class    string
	Severity string
	Downtime struct {
		UUID        string   `json:"id" gorm:"primaryKey"`
		ServerName  string   `json:"serverName" gorm:"index"`   // Empty in Origin/Cache; not empty in Registry
		CreatedBy   string   `json:"createdBy" gorm:"not null"` // Person who created this downtime
		UpdatedBy   string   `json:"updatedBy" gorm:"not null"` // Person who last updated this downtime
		Source      string   `json:"source" gorm:"not null"`    // Pelican service that set this downtime
		Class       Class    `json:"class" gorm:"not null"`     // SCHEDULED or UNSCHEDULED
		Description string   `json:"description" gorm:"type:text"`
		Severity    Severity `json:"severity" gorm:"type:varchar(80);not null"`
		StartTime   int64    `json:"startTime" gorm:"not null;index"` // Epoch UTC
		EndTime     int64    `json:"endTime" gorm:"not null;index"`   // Epoch UTC
		CreatedAt   int64    `json:"createdAt" gorm:"autoCreateTime:milli"`
		UpdatedAt   int64    `json:"updatedAt" gorm:"autoUpdateTime:milli"`
		DeletedAt   *int64   `json:"deletedAt"`
	}

	// Common attributes necessary for all server ads
	ServerBaseAd struct {
		Name         string    `json:"name"`
		StartTime    int64     `json:"startTime"`    // The start time of the server ad.  Unix timestamp
		InstanceID   string    `json:"instanceID"`   // The instance ID of the server ad (hex-encoded UUID).
		GenerationID uint64    `json:"generationID"` // A monotonically-increasing counter that's incremented every time a new server ad is generated.  Will always be nonzero if known
		Version      string    `json:"version"`      // Version of Pelican that produced the ad
		Expiration   time.Time `json:"expiry"`       // Expiration time of the ad
	}

	// An interface for dealing with server ads
	ServerBaseAdInterface interface {
		GetName() string          // The name of the server ad
		GetStartTime() int64      // The start time, in seconds, of the server ad.  Unix timestamp
		GetInstanceID() string    // The instance ID of the server ad (currently a hex-encoded UUID; may change).
		GetGenerationID() uint64  // The generation ID (monotonic counter) of the server ad; incremented every time a process generates a new ad.
		GetVersion() string       // The version of the server base ad
		GetExpiration() time.Time // Time at which the ad will expire
	}

	// A representation of a known director endpoint.
	//
	// Intended for building an in-memory table of known directors
	// so services can advertise to all directors in a federation
	DirectorAd struct {
		ServerBaseAd
		AdvertiseUrl string `json:"advertise_url"` // The URL / endpoint where the director expects ads to be POST'd
	}

	// ** BE WARNED **
	// This struct needs to be kept in sync with BOTH the director/director_ui.go:listServerResponse and the director/director_ui.go:serverResponse
	ServerAd struct {
		ServerBaseAd
		RegistryPrefix      string            `json:"registryPrefix"` // The server's prefix recorded in the registry
		StorageType         OriginStorageType `json:"storageType"`    // Always POSIX for caches
		DisableDirectorTest bool              `json:"directorTest"`
		AuthURL             url.URL           `json:"auth_url"`
		BrokerURL           url.URL           `json:"broker_url"` // The URL of the broker service to use for this host.
		URL                 url.URL           `json:"url"`        // This is server's XRootD URL for file transfer
		WebURL              url.URL           `json:"web_url"`    // This is server's Web interface and API
		Type                string            `json:"type"`
		Latitude            float64           `json:"latitude"`
		Longitude           float64           `json:"longitude"`
		Caps                Capabilities      `json:"capabilities"`
		FromTopology        bool              `json:"from_topology"`
		IOLoad              float64           `json:"io_load"`
		Downtimes           []Downtime        `json:"downtimes,omitempty"` // Allow null values if no downtime
		RequiredFeatures    []string          `json:"requiredFeatures"`    // A list of feature names required by this server
		Status              string            `json:"status"`
	}

	// The struct holding a server's advertisement (including ServerAd and NamespaceAd)
	Advertisement struct {
		sync.RWMutex
		ServerAd
		NamespaceAds []NamespaceAdV2
	}

	StrategyType string
	SortType     string

	OriginAdvertiseV2 struct {
		ServerBaseAd
		// The namespace prefix to register/look up the server in the registry.
		// The value is /caches/{Xrootd.Sitename} for cache servers and /origins/{Xrootd.Sitename} for the origin servers
		RegistryPrefix string `json:"registry-prefix"`
		BrokerURL      string `json:"broker-url,omitempty"`
		DataURL        string `json:"data-url" binding:"required"`
		WebURL         string `json:"web-url,omitempty"`
		// TODO: Deprecate top level "Origin" caps -- each namespace should have its own caps that
		// express what the origin is willing to do on the namespace's behalf. This helps us work
		// around the lack of a concept for "globally-defined" namespaces.
		Caps                Capabilities      `json:"capabilities"`
		Namespaces          []NamespaceAdV2   `json:"namespaces"`
		Issuer              []TokenIssuer     `json:"token-issuer"`
		StorageType         OriginStorageType `json:"storageType"`
		DisableDirectorTest bool              `json:"directorTest"`        // Use negative attribute (disable instead of enable) to be BC with legacy servers where they don't have this field
		Downtimes           []Downtime        `json:"downtimes,omitempty"` // Allow null values if no downtime
		RequiredFeatures    []string          `json:"requiredFeatures"`
		Now                 time.Time         `json:"now"` // Populated when ad is sent to the director; otherwise, may be zero.  Used to detect time skews between client and server
		Status              string			  `json:"status"` // The status of the server ad. This is a human-readable string that describes the server's status.
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
		Timestamp int64  `json:"timestamp"` // Unix time, the number of seconds elapsed since January 1, 1970 UTC.
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

	XPelHeader interface {
		GetName() string
		ParseRawHeader(*http.Response) error
	}

	XPelAuth struct {
		Issuers []*url.URL
	}

	XPelNs struct {
		Namespace      string // Federation Prefix path
		RequireToken   bool   // Whether or not a token is required for read operations
		CollectionsUrl *url.URL
	}

	XPelTokGen struct {
		Issuers       []*url.URL
		MaxScopeDepth uint
		Strategy      StrategyType
		BasePaths     []string
		VaultServer   *url.URL
	}

	ClientRedirectInfo struct {
		Lat           float64 `json:"lat"`
		Lon           float64 `json:"lon"`
		GeoIpRadiusKm uint16  `json:"geoIpRadiusKm"` // 0 will indicate no radius (i.e. no resolution)
		Resolved      bool    `json:"resolved"`      // whether or not the client IP was resolved by MaxMind
		FromTTLCache  bool    `json:"fromTtlcache"`  // whether we're using a cached value
		IpAddr        string  `json:"ipAddr"`
	}

	ServerRedirectInfo struct {
		Lat        float64 `json:"lat"`
		Lon        float64 `json:"lon"`
		HasObject  string  `json:"hasObject"`
		LoadWeight float64 `json:"loadWeight"`
	}

	RedirectInfo struct {
		ClientInfo         ClientRedirectInfo             `json:"clientInfo"`
		ServersInfo        map[string]*ServerRedirectInfo `json:"serversInfo"`
		DirectorSortMethod string                         `json:"directorSortMethod"`
	}

	DirectorResponse struct {
		ObjectServers []*url.URL // List of servers provided in Link header
		Location      *url.URL   // URL content of the location header
		XPelAuthHdr   XPelAuth
		XPelNsHdr     XPelNs
		XPelTokGenHdr XPelTokGen
	}

	AdAfter int // Ternary logic for the `Ad.After` function
)

var (
	// Instance ID and "startup" time.
	// Both of these can be reset by unit tests so the startup
	// time might not be the actual process launch time.
	instanceOnce sync.Once
	instanceID   string
	startTime    int64

	// Counter for the current server ad generation ID
	generationID atomic.Uint64
)

const (
	SCHEDULED   Class = "SCHEDULED"
	UNSCHEDULED Class = "UNSCHEDULED"
)

const (
	Outage                      Severity = "Outage (completely inaccessible)"
	Severe                      Severity = "Severe (most services down)"
	IntermittentOutage          Severity = "Intermittent Outage (may be up for some of the time)"
	NoSignificantOutageExpected Severity = "No Significant Outage Expected (you shouldn't notice)"
)

// Indicate the downtime is ongoing indefinitely.
// We chose -1 to avoid the default value (0) of the int64 type
const IndefiniteEndTime int64 = -1

func (x XPelNs) GetName() string {
	return "X-Pelican-Namespace"
}
func (x *XPelNs) ParseRawResponse(resp *http.Response) error {
	raw := resp.Header.Values(x.GetName())
	if len(raw) == 0 {
		return errors.Errorf("No %s header found.", x.GetName())
	}
	keyDict := utils.HeaderParser(raw[0])
	x.Namespace = keyDict["namespace"]
	x.RequireToken, _ = strconv.ParseBool(keyDict["require-token"])
	if keyDict["collections-url"] != "" {
		x.CollectionsUrl, _ = url.Parse(keyDict["collections-url"])
	}
	return nil
}

func (x XPelAuth) GetName() string {
	return "X-Pelican-Authorization"
}
func (x *XPelAuth) ParseRawResponse(resp *http.Response) error {
	// If the director provides an auth header, raw will have an array of length 1.
	raw := resp.Header.Values(x.GetName())
	if len(raw) > 0 {
		x.Issuers = make([]*url.URL, 0)
		// clean up the string and split it by commas to fetch each issuer. Can't use
		// utils.HeaderParser, because we don't have unique keys here.
		cleaned := strings.ReplaceAll(raw[0], " ", "")
		issuers := strings.Split(cleaned, ",")
		for _, issuer := range issuers {
			issuerUrlStr := strings.TrimPrefix(issuer, "issuer=")
			issuerUrl, err := url.Parse(issuerUrlStr)
			if err != nil {
				return errors.Errorf("Failed to parse issuer URL %s from Director's %s header: %v", issuerUrlStr, x.GetName(), err)
			}
			x.Issuers = append(x.Issuers, issuerUrl)
		}
	}
	return nil
}

func (x XPelTokGen) GetName() string {
	return "X-Pelican-Token-Generation"
}
func (x *XPelTokGen) ParseRawResponse(resp *http.Response) error {
	raw := resp.Header.Values(x.GetName())
	if len(raw) > 0 {
		// Parse issuer, for now assuming a single value but eventually may be multiple
		x.Issuers = make([]*url.URL, 0)
		keyDict := utils.HeaderParser(raw[0])
		issuerUrl, err := url.Parse(keyDict["issuer"])
		if err != nil {
			return errors.Errorf("Failed to parse issuer URL %s from Director's %s header: %v", keyDict["issuer"], x.GetName(), err)
		}
		x.Issuers = append(x.Issuers, issuerUrl)

		// Parse scope depth
		maxScopeDepth, err := strconv.ParseUint(keyDict["max-scope-depth"], 10, 32)
		if err != nil {
			return errors.Errorf("Failed to parse max-scope-depth %s from Director's %s header: %v", keyDict["max-scope-depth"], x.GetName(), err)
		}
		x.MaxScopeDepth = uint(maxScopeDepth)

		// Parse strategy
		strategy, exists := keyDict["strategy"]
		if !exists {
			return errors.Errorf("No credential generation strategy found in Director's %s header", x.GetName())
		}
		if !IsValidStrategy(strategy) {
			return errors.Errorf("Invalid strategy '%s' from Director's %s header", strategy, x.GetName())
		}
		x.Strategy = StrategyType(strategy)

		// Parse base path(s) -- Right now we assume a single value, although this may eventually change.
		basePath, exists := keyDict["base-path"]
		if exists {
			x.BasePaths = append(x.BasePaths, basePath)
		}

		// Handle potential for vault server in header
		vaultServer, exists := keyDict["vault-server"]
		if exists {
			vaultServerUrl, err := url.Parse(vaultServer)
			if err != nil {
				return errors.Errorf("Failed to parse vault server URL %s from Director's %s header: %v", vaultServer, x.GetName(), err)
			}
			x.VaultServer = vaultServerUrl
		}
	}
	return nil
}

func NewRedirectInfoFromIP(ipAddr string) *RedirectInfo {
	return &RedirectInfo{
		ClientInfo: ClientRedirectInfo{
			IpAddr: ipAddr,
		},
		ServersInfo: map[string]*ServerRedirectInfo{},
	}
}

const (
	OAuthStrategy StrategyType = "OAuth2"
	VaultStrategy StrategyType = "Vault"
)

const (
	// SortType for sorting the server ads
	DistanceType        SortType = "distance"
	DistanceAndLoadType SortType = "distanceAndLoad"
	RandomType          SortType = "random"
	AdaptiveType        SortType = "adaptive"

	AdAfterFalse   AdAfter = 0 // The ad was *not* generated after the compared one
	AdAfterTrue    AdAfter = 1 // The ad was generated after the compared one
	AdAfterUnknown AdAfter = 2 // One of the ads in the comparison is missing necessary attributes to determine when it was generated
)

func IsValidStrategy(strategy string) bool {
	switch StrategyType(strategy) {
	case OAuthStrategy, VaultStrategy:
		return true
	default:
		return false
	}
}

// Return the version of the `ad`
//
// Getter for ServerAdBase to fulfill the ServerBaseAdInterface
func (ad ServerBaseAd) GetVersion() string {
	return ad.Version
}

// Return the instance ID of the `ad`
//
// Getter for ServerAdBase to fulfill the ServerBaseAdInterface
func (ad ServerBaseAd) GetInstanceID() string {
	return ad.InstanceID
}

// Return the generation ID of the `ad`
//
// Getter for ServerAdBase to fulfill the ServerBaseAdInterface
func (ad ServerBaseAd) GetGenerationID() uint64 {
	return ad.GenerationID
}

// Return the start time of the `ad`
//
// Getter for ServerAdBase to fulfill the ServerBaseAdInterface
func (ad ServerBaseAd) GetStartTime() int64 {
	return ad.StartTime
}

// Return the name of the `ad`
//
// Getter for ServerAdBase to fulfill the ServerBaseAdInterface
func (ad ServerBaseAd) GetName() string {
	return ad.Name
}

// Return the ad's expiration time
//
// Getter for ServerAdBase to fulfill the ServerBaseAdInterface
func (ad ServerBaseAd) GetExpiration() time.Time {
	return ad.Expiration
}

// Returns true if `ad` was generated after `other`,
func (ad *ServerBaseAd) After(other ServerBaseAdInterface) AdAfter {
	// Handle the error condition -- the ad names must match.
	if ad.Name != other.GetName() {
		return AdAfterUnknown
	}

	// Next, see if there's any ad metadata missing or unset.
	if ad.StartTime == 0 || other.GetStartTime() == 0 {
		return AdAfterUnknown
	}
	if ad.InstanceID == "" || other.GetInstanceID() == "" {
		return AdAfterUnknown
	}
	if ad.GenerationID == 0 || other.GetGenerationID() == 0 {
		return AdAfterUnknown
	}

	// We've determined the two ads are from a server with the
	// same name.  However, if the server had restarted recently,
	// they might be from distinct instances of that server (e.g.,
	// different PIDs on the same host).  Detect that by looking at
	// the start time and the randomly-generated instance ID.
	if ad.StartTime > other.GetStartTime() {
		return AdAfterTrue
	} else if ad.StartTime < other.GetStartTime() {
		return AdAfterFalse
	} else if ad.InstanceID > other.GetInstanceID() {
		return AdAfterTrue
	} else if ad.InstanceID < other.GetInstanceID() {
		return AdAfterFalse
	}

	// The ads were generated by the same process; compare the monotonically
	// increasing counter!
	if ad.GenerationID > other.GetGenerationID() {
		return AdAfterTrue
	}
	return AdAfterFalse
}

// Set the common defaults for the server ad
//
// Defaults include the generation and instance IDs, allowing
// remote services to determine "when" the ad was generated
func (ad *ServerBaseAd) Initialize(name string) {
	ad.Name = name
	instanceID, startTime := getInstanceID()
	ad.InstanceID = instanceID
	ad.StartTime = startTime
	ad.GenerationID = generationID.Add(1) + 1
	adLifetime := param.Server_AdLifetime.GetDuration()
	// Not all unit tests initializae the config, meaning adLifetime
	// may be 0.
	if adLifetime == 0 {
		adLifetime = 15 * time.Minute
	}
	ad.Expiration = time.Now().Add(adLifetime)
	ad.Version = version.GetVersion()
}

// Copy the base attributes from a given `other` ad to `ad`
func (ad *ServerBaseAd) CopyFrom(other ServerBaseAdInterface) {
	ad.Name = other.GetName()
	ad.InstanceID = other.GetInstanceID()
	ad.StartTime = other.GetStartTime()
	ad.GenerationID = other.GetGenerationID()
	ad.Version = other.GetVersion()
	ad.Expiration = other.GetExpiration()
}

// Various getters

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
	// out to a newer version of the director
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
	//isn't the most efficient way of doing so (an interactive search as opposed to some sort
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
				Caps: caps,
				Path: nsAd.Path,
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
		DataURL:    oAd1.URL,
		WebURL:     oAd1.WebURL,
		Caps:       caps,
		Namespaces: nsAdsV2,
		Issuer:     tokIssuers,
	}
	oAd2.Initialize(oAd1.Name)
	return oAd2
}

func ServerAdsToServerNameURL(ads []ServerAd) (output string) {
	for _, ad := range ads {
		output += ad.Name + ":" + ad.URL.String() + "\n"
	}
	return
}

// Reset the state of the server ad tracking for the process
//
// Will cause newly-generated server ads to appear to be from a new process.
// Intended for unit tests; is not thread-safe
func Reset() {
	instanceOnce = sync.Once{}
}

// Get the "instance ID" of the running process
//
// The instance ID is a randomly-generated UUID, hex-encoded, identifying
// the currently-running process.  The intent is external entities (i.e.,
// the director), can differentiate between different server instances with
// the same name by seeing if they claim to have different instance IDs.
func getInstanceID() (string, int64) {
	instanceOnce.Do(func() {
		instanceID = uuid.New().String()
		startTime = time.Now().Unix()
	})

	return instanceID, startTime
}
