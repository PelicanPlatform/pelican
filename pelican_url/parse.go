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
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/pkg/errors"
)

type (
	PelicanURLValues map[string][]string

	PelicanURL struct {
		Scheme    string
		RawScheme string
		Host      string
		Path      string
		RawQuery  string

		FedInfo FederationDiscovery
	}

	SchemeError struct {
		Scheme string
	}

	parseOptions struct {
		shouldDiscover          bool
		validateQueryParams     bool
		allowUnknownQueryParams bool
	}
	ParseOption func(*parseOptions)
)

const (
	OsdfScheme    string = "osdf"
	StashScheme   string = "stash"
	PelicanScheme string = "pelican"

	PelicanDiscoveryPath string = "/.well-known/pelican-configuration"
)

var (
	ValidSchemes = []string{OsdfScheme, StashScheme, PelicanScheme}
)

func (e *SchemeError) Error() string {
	return fmt.Sprintf("scheme '%s' not understood. If present, schemes must be one of '%s', '%s', or '%s'", e.Scheme, PelicanScheme, OsdfScheme, StashScheme)
}

func (p *PelicanURL) String() string {
	u := &url.URL{
		Scheme:   p.Scheme,
		Host:     p.Host,
		Path:     p.Path,
		RawQuery: p.RawQuery,
	}
	return u.String()
}

func (p *PelicanURL) GetTokenName() string {
	u := &url.URL{
		Scheme: p.RawScheme,
	}
	return stripTokenFromUrl(u)
}

func (p *PelicanURL) Query() PelicanURLValues {
	u := &url.URL{
		Scheme:   p.Scheme,
		Host:     p.Host,
		Path:     p.Path,
		RawQuery: p.RawQuery,
	}
	return PelicanURLValues(u.Query())
}

func (p *PelicanURL) GetRawUrl() *url.URL {
	u := &url.URL{
		Scheme:   p.Scheme,
		Host:     p.Host,
		Path:     p.Path,
		RawQuery: p.RawQuery,
	}
	return u
}

// Parse Options
func ShouldDiscover(d bool) ParseOption {
	return func(po *parseOptions) {
		po.shouldDiscover = d
	}
}

func ValidateQueryParams(d bool) ParseOption {
	return func(po *parseOptions) {
		po.validateQueryParams = d
	}
}

func AllowUnknownQueryParams(d bool) ParseOption {
	return func(po *parseOptions) {
		po.allowUnknownQueryParams = d
	}
}

// Check whether the provided scheme is one Peliacan understands
func schemeUnderstood(scheme string) bool {
	for _, validScheme := range ValidSchemes {
		// HTCondor may prepend token+ to the scheme, so we need to allow that
		if scheme == validScheme || strings.HasSuffix(scheme, "+"+validScheme) {
			return true
		}
	}
	return false
}

// Given a scheme that may have an embedded token, normalize it to the base scheme.
func normalizeScheme(scheme string) string {
	return strings.Split(scheme, "+")[len(strings.Split(scheme, "+"))-1]
}

// Get any scheme-embedded tokens, Condor-style 😎
func stripTokenFromUrl(destination *url.URL) (tokenName string) {
	schemePieces := strings.Split(destination.Scheme, "+")
	tokenName = ""
	// If there are 2 or more pieces, token name is everything but the last item, joined with a +
	if len(schemePieces) > 1 {
		tokenName = strings.Join(schemePieces[:len(schemePieces)-1], "+")
	}
	return
}

func correctUrlWithUnderscore(sourceUrl *url.URL) {
	sourceUrl.Scheme = strings.ReplaceAll(sourceUrl.Scheme, "_", ".")
}

// Given an OSDF URL like osdf://foo/bar, normalize it to osdf:///foo/bar
// This also applies to stash URLs
func normalizeOSDFTripleSlash(parsedUrl *url.URL) (err error) {
	if parsedUrl.Scheme == OsdfScheme || parsedUrl.Scheme == StashScheme {
		if parsedUrl.Host != "" {
			var objPath string
			objPath, err = url.JoinPath(parsedUrl.Host, parsedUrl.Path)
			if err != nil {
				err = errors.Wrapf(err, "failed to normalize osdf/stash url %s", parsedUrl.String())
				return
			}
			parsedUrl.Path = path.Join("/", objPath)
			parsedUrl.Host = ""
		}
	}
	return
}

func validateOsdfStashUrl(parsedUrl *url.URL) error {
	return normalizeOSDFTripleSlash(parsedUrl)
}

func validatePelicanUrl(parsedUrl *url.URL) error {
	if parsedUrl.Host == "" {
		return errors.New(fmt.Sprintf("pelican URL '%s' is invalid because it has no host", parsedUrl.String()))
	}
	return nil
}

// Remote URLs may look like:
//  1. osdf:///foo/bar (good osdf URL, but requires a discovery URL)
//  2. osdf://foo/bar (user forgot triple /, otherwise okay with discovery URL)
//  3. stash-equivalent variants of OSDF URLs (i.e. stash:///foo/bar, stash://foo/bar)
//  4. /foo/bar (federation not specified, treated as Pelican and requires discovery URL)
//  5. pelican://<discoveryUrl>/foo/bar (good Pelican URL)
func Parse(rawUrl string, parseOpts []ParseOption, discoveryOpts []DiscoveryOption) (*PelicanURL, error) {
	// handle any incoming options
	pOpts := &parseOptions{}
	dOpts := &discoveryOptions{}
	for _, opt := range parseOpts {
		opt(pOpts)
	}
	for _, opt := range discoveryOpts {
		opt(dOpts)
	}

	p := &PelicanURL{}
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}

	// Handle case 4
	if parsedUrl.Scheme == "" {
		// The only time it's okay to parse a schemeless Pelican URL is if the discovery URL
		// is also provided. Otherwise, we can't know what to do with it. If we _do_ have the
		// discovery URL, treat the scheme as pelican://
		if dOpts.discoveryUrl == nil {
			return nil, errors.New("schemeless Pelican URLs must be used with a federation discovery URL")
		}

		parsedUrl.Scheme = PelicanScheme
		parsedUrl.Host = dOpts.discoveryUrl.Host
	}

	// Correct schemes from HTCondor with underscores
	correctUrlWithUnderscore(parsedUrl)

	// Verify that the scheme is understood. Note that parsing of schemeless URLs is generally allowed in Pelican
	// if the user has configured Federation.DiscoveryUrl/DirectorUrl in their config or run the client with `-f <discovery-url>`.
	// However, the object paths should be combined with the discovery URL to form a complete URL _before_ trying to
	// parse it as a PelicanURL. This allows URL parsing to be ambivalent about config.
	if !schemeUnderstood(parsedUrl.Scheme) {
		return nil, &SchemeError{Scheme: parsedUrl.Scheme}
	}

	// Handle case 2 normalization
	normedScheme := normalizeScheme(parsedUrl.Scheme)
	if normedScheme == OsdfScheme || normedScheme == StashScheme {
		err = validateOsdfStashUrl(parsedUrl)
		if err != nil {
			return nil, err
		}
	} else { // Make sure Pelican URLs have a host
		err = validatePelicanUrl(parsedUrl)
		if err != nil {
			return nil, err
		}
	}

	// Normalize the scheme (e.g. foo+osdf -> osdf) and populate the raw scheme for use by token-fetching functions
	p.Scheme = normedScheme
	p.RawScheme = parsedUrl.Scheme
	p.Host = parsedUrl.Host
	p.Path = parsedUrl.Path
	p.RawQuery = parsedUrl.RawQuery

	if pOpts.validateQueryParams {
		err = p.ValidateQueryParams(AllowUnknownQueryParams(pOpts.allowUnknownQueryParams))
	}

	// This is potentially the most expensive thing we do during parsing,
	// so only do it once everything else has been validated
	if pOpts.shouldDiscover {
		// guarantee cases 1/2 have a discovery URL
		opts := []DiscoveryOption{WithContext(dOpts.ctx), WithClient(dOpts.httpClient), UseCached(dOpts.useCached), WithUserAgent(dOpts.userAgent), WithDiscoveryUrl(dOpts.discoveryUrl)}
		err = p.PopulateFedInfo(opts...)
	}

	return p, err
}
