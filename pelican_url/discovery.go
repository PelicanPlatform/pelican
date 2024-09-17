/***************************************************************
*
* Copyright (C) 2024, University of Nebraska-Lincoln
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

package pelican_url

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

type (
	MetadataErr struct {
		msg      string
		innerErr error
	}

	FederationDiscovery struct {
		DiscoveryEndpoint string `json:"discovery_endpoint"`
		DirectorEndpoint  string `json:"director_endpoint"`
		RegistryEndpoint  string `json:"namespace_registration_endpoint"`
		JwksUri           string `json:"jwks_uri"`
		BrokerEndpoint    string `json:"broker_endpoint"`
	}

	discoveryOptions struct {
		ctx          context.Context
		httpClient   *http.Client
		discoveryUrl *url.URL // for osdf/stash URLs that don't have a discovery URL baked into their host
		userAgent    string
		useCached    bool
	}
	DiscoveryOption func(*discoveryOptions)

	// Stuff used by the pelican URL Cache (which prevents querying the Director
	// for metadata on the same URL more than once every 30 minutes)
	cacheItem struct {
		fedInfo FederationDiscovery
		err     error
	}

	Cache = ttlcache.Cache[string, cacheItem]
)

var (
	MetadataTimeoutErr *MetadataErr = &MetadataErr{msg: "Timeout when querying metadata"}

	successTTL      = ttlcache.DefaultTTL
	failureTTL      = 5 * time.Minute
	pelicanUrlCache *Cache

	// Not a constant, because we want to be able to change it in tests
	OsdfDiscoveryHost string = "osg-htc.org"
)

// This function sets the OSDF discovery host, only meant for testing purposes where we don't
// want to perform real OSDF discovery. This is not thread-safe and should only be used in tests.
func SetOsdfDiscoveryHost(host string) (oldHost string, er error) {
	// If they haven't passed a scheme, we'll assume https. While we don't actually care about the
	// scheme here, the url.Parse function does, as it says parsing something without a scheme is
	// somewhat undefined.
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	url, err := url.Parse(host)
	if err != nil {
		return "", err
	}

	oldHost = OsdfDiscoveryHost
	OsdfDiscoveryHost = url.Host
	return
}

func StartCache() *Cache {
	// Start the cache with a default suppressed loader. Later on when we need to call
	// Get() on the cache, we can pass in a loader that uses specific DiscoveryOptions
	baseLoader := getDynamicLoader(
		WithContext(context.Background()),
		WithClient(&http.Client{Timeout: 5 * time.Second}),
	)
	suppressedLoader := ttlcache.NewSuppressedLoader(baseLoader, new(singleflight.Group))
	pelicanURLCache := ttlcache.New(
		ttlcache.WithTTL[string, cacheItem](30*time.Minute),
		ttlcache.WithLoader(suppressedLoader),
	)

	// Start our cache for url metadata
	// This is stopped in the `Shutdown` method
	go pelicanURLCache.Start()
	return pelicanURLCache
}

// This function creates a new MetadataError by wrapping the previous error
func NewMetadataError(err error, msg string) *MetadataErr {
	return &MetadataErr{
		msg:      msg,
		innerErr: err,
	}
}

func (e *MetadataErr) Error() string {
	// If the inner error is nil, we don't want to print out "<nil>"
	if e.innerErr != nil {
		return fmt.Sprintf("%s: %v", e.msg, e.innerErr)
	} else {
		return e.msg
	}
}

func (e *MetadataErr) Is(target error) bool {
	// We want to verify we have a timeout error
	if target, ok := target.(*MetadataErr); ok {
		return e.msg == target.msg
	}
	return false
}

func (e *MetadataErr) Wrap(err error) error {
	return &MetadataErr{
		innerErr: err,
		msg:      e.msg,
	}
}

func (e *MetadataErr) Unwrap() error {
	return e.innerErr
}

// Discovery Options, passed to Parse and PopulateFedInfo
func WithContext(ctx context.Context) DiscoveryOption {
	return func(do *discoveryOptions) {
		do.ctx = ctx
	}
}

func WithClient(client *http.Client) DiscoveryOption {
	return func(do *discoveryOptions) {
		do.httpClient = client
	}
}

func WithDiscoveryUrl(url *url.URL) DiscoveryOption {
	return func(do *discoveryOptions) {
		do.discoveryUrl = url
	}
}

func UseCached(d bool) DiscoveryOption {
	return func(do *discoveryOptions) {
		do.useCached = d
	}
}

func WithUserAgent(ua string) DiscoveryOption {
	return func(do *discoveryOptions) {
		do.userAgent = ua
	}
}

// Whenever we Get() an item from the cache, the defined loader tries to generate the item if it
// doesn't already exist. For federation metadata, this means querying the Director, which means
// we need to pass things like the context and http client to the loader. Because these are set up
// in config (which we don't want to import here because of cyclic dependencies), we need a way to
// pass them to the loader. This function creates a loader that can accept these options so that the
// client can load config and pass it all the way down to the Director query.
func getDynamicLoader(opts ...DiscoveryOption) ttlcache.LoaderFunc[string, cacheItem] {
	options := &discoveryOptions{}
	for _, opt := range opts {
		opt(options)
	}

	loader := ttlcache.LoaderFunc[string, cacheItem](
		func(c *ttlcache.Cache[string, cacheItem], key string) *ttlcache.Item[string, cacheItem] {
			var ctx context.Context
			var cancel context.CancelFunc
			if options.ctx == nil {
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
			} else {
				ctx = options.ctx
			}

			var httpClient *http.Client
			if options.httpClient != nil {
				httpClient = options.httpClient
			} else {
				httpClient = &http.Client{
					Timeout: time.Second * 5,
				}
			}

			discoveryUrl, err := url.Parse(key)
			if err != nil {
				item := c.Set(key, cacheItem{err: err}, failureTTL)
				return item
			}

			var ua string
			if options.userAgent != "" {
				ua = options.userAgent
			} else {
				ua = "pelican"
			}

			fedInfo, err := DiscoverFederation(ctx, httpClient, ua, discoveryUrl)
			if err != nil {
				// Set a shorter TTL for failures
				item := c.Set(key, cacheItem{err: err}, failureTTL)
				return item
			}

			// Set a longer TTL for successes
			item := c.Set(key, cacheItem{fedInfo: fedInfo}, successTTL)
			return item
		},
	)

	return loader
}

// Helper function to start a metadata request.
//
// We see periodic timeouts when doing metadata lookup at sites.
// Adding a modest retry will, hopefully, reduce the number of errors
// that propagate out to users
func startMetadataQuery(ctx context.Context, httpClient *http.Client, ua string, discoveryUrl *url.URL) (result *http.Response, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryUrl.String(), nil)
	if err != nil {
		err = errors.Wrapf(err, "Failure when doing federation metadata request creation for %s", discoveryUrl)
		return
	}

	if ua != "" {
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", "pelican")
	}

	result, err = httpClient.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			err = MetadataTimeoutErr.Wrap(err)
		} else {
			err = NewMetadataError(err, "Error occurred when querying for metadata")
		}
	}
	return
}

// This function is for discovering federations as specified by a url during a pelican:// transfer.
// this does not populate global fields and is more temporary per url
func DiscoverFederation(ctx context.Context, httpClient *http.Client, ua string, discoveryUrl *url.URL) (metadata FederationDiscovery, err error) {
	log.Debugln("Performing federation service discovery for against", discoveryUrl.String())
	discoveryUrl.Path = PelicanDiscoveryPath

	var result *http.Response
	for idx := 1; idx <= 3; idx++ {
		result, err = startMetadataQuery(ctx, httpClient, ua, discoveryUrl)
		if err == nil {
			break
		} else if errors.Is(err, MetadataTimeoutErr) && ctx.Err() == nil {
			log.Warningln("Timeout occurred when querying discovery URL", discoveryUrl.String(), "for metadata;", 3-idx, "retries remaining")
			time.Sleep(2 * time.Second)
		} else {
			return
		}
	}
	if errors.Is(err, MetadataTimeoutErr) {
		log.Errorln("3 timeouts occurred when querying discovery URL", discoveryUrl.String())
		return
	}

	if result.Body != nil {
		defer result.Body.Close()
	}

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return FederationDiscovery{}, errors.Wrapf(err, "Failure when doing federation metadata read to %s", discoveryUrl)
	}

	if result.StatusCode != http.StatusOK {
		truncatedMessage := string(body)
		if len(body) > 1000 {
			truncatedMessage = string(body[:1000])
			truncatedMessage += " [... remainder truncated ...]"
		}
		return FederationDiscovery{}, errors.Errorf("Federation metadata discovery failed with HTTP status %d.  Error message: %s", result.StatusCode, truncatedMessage)
	}

	metadata = FederationDiscovery{}
	err = json.Unmarshal(body, &metadata)
	if err != nil {
		return FederationDiscovery{}, errors.Wrapf(err, "Failure when parsing federation metadata at %s", discoveryUrl)
	}

	log.Debugln("Federation service discovery resulted in director URL", metadata.DirectorEndpoint)
	log.Debugln("Federation service discovery resulted in registry URL", metadata.RegistryEndpoint)
	log.Debugln("Federation service discovery resulted in JWKS URL", metadata.JwksUri)
	log.Debugln("Federation service discovery resulted in broker URL", metadata.BrokerEndpoint)

	return metadata, nil
}

func (p *PelicanURL) PopulateFedInfo(opts ...DiscoveryOption) error {
	p.FedInfo = FederationDiscovery{}

	// It's rare that I wish Go were more like C++, but the inability to overload functions is one of those times...
	// To achieve something similar, this uses options to allow (but not require) passing config to the function.
	// This architecture lets us split pelican URLs into their own package that can be imported by things like
	// config, even though this suite of functions needs access to some config values like client timeouts,
	// OSDF defaults, user agent headers, etc.
	options := &discoveryOptions{}
	for _, opt := range opts {
		opt(options)
	}

	discoveryUrl := &url.URL{Scheme: "https", Path: PelicanDiscoveryPath}
	normedScheme := normalizeScheme(p.Scheme)
	if normedScheme == OsdfScheme || normedScheme == StashScheme {
		// Prefer OSDF discovery host, but allow someone to overwrite if they really want to
		if options.discoveryUrl == nil {
			discoveryUrl.Host = OsdfDiscoveryHost
		} else {
			if options.discoveryUrl.Host != OsdfDiscoveryHost {
				log.Warningf("%s was provided as a discovery URL for %s. Are you sure this is what you want to do?", options.discoveryUrl.String(), p.String())
			}
			discoveryUrl.Host = options.discoveryUrl.Host
		}
	} else if normedScheme == PelicanScheme {
		if options.discoveryUrl != nil && p.Host != options.discoveryUrl.Host {
			log.Warningf("%s was provided as a discovery URL for Pelican URL %s. Ignoring hostname from Pelican URL. Are you sure this is what you want to do?", options.discoveryUrl.Host, p.String())
			discoveryUrl.Host = options.discoveryUrl.Host
		} else {
			// We should be able to grab the discovery host from the parsed URL.
			discoveryUrl.Host = p.Host
		}
	} else if normedScheme != "" {
		return errors.New(fmt.Sprintf("Unknown scheme %s in Pelican URL %s", p.Scheme, p.String()))
	}

	if discoveryUrl.Host == "" {
		return errors.New(fmt.Sprintf("Unable to determine discovery host for Pelican URL %s", p.String()))
	}

	var httpClient *http.Client
	if options.httpClient != nil {
		httpClient = options.httpClient
	} else {
		httpClient = &http.Client{
			Timeout: time.Second * 5,
		}
	}

	var ctx context.Context
	if options.ctx != nil {
		ctx = options.ctx
	} else {
		ctx = context.Background()
	}

	if options.useCached {
		if pelicanUrlCache == nil {
			pelicanUrlCache = StartCache()
		}

		item := pelicanUrlCache.Get(discoveryUrl.String(), ttlcache.WithLoader(getDynamicLoader(WithClient(httpClient), WithContext(ctx))))
		if item != nil {
			if item.Value().err != nil {
				return item.Value().err
			}

			p.FedInfo = item.Value().fedInfo
			log.Debugln("Using cached federation info for", discoveryUrl.String())
			return nil
		}
	}

	// TODO: Figure out best way to get version into this
	// var userAgent string
	// if options.userAgent != "" {
	// 	userAgent = options.userAgent
	// } else {

	fedInfo, err := DiscoverFederation(ctx, httpClient, options.userAgent, discoveryUrl)
	if err != nil {
		return err
	}

	p.FedInfo = fedInfo
	p.FedInfo.DiscoveryEndpoint = discoveryUrl.String()

	return nil
}
