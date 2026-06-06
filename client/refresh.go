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

package client

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
)

// RefreshExpiringCredentials proactively refreshes stored OAuth2 tokens in the
// user's credential wallet that will expire within the given window, using a
// non-interactive refresh-token grant.
//
// For each credential the issuer's token endpoint is resolved either directly
// (when the credential is keyed by an issuer URL) or via a Director lookup for
// the namespace prefix. The wallet is read once and, if any token is
// refreshed, written back; the number of tokens refreshed is returned.
//
// This is intended for long-running daemons (the client agent) that keep the
// wallet open. Callers should serialize concurrent invocations. Note that the
// per-transfer client path performs its own lazy refresh of *expired* tokens;
// keeping this window comfortably larger than typical transfer durations
// avoids the two paths racing on the same credential.
func RefreshExpiringCredentials(ctx context.Context, within time.Duration) (int, error) {
	osdfConfig, err := config.GetCredentialConfigContents()
	if err != nil {
		return 0, errors.Wrap(err, "failed to read credential wallet")
	}

	cutoff := time.Now().Add(within)
	refreshed := 0

	// Credentials are stored per-federation, keyed by discovery URL.
	for discovery, fc := range osdfConfig.Federation {
		for pi := range fc.OauthClient {
			entry := &fc.OauthClient[pi]
			if !entryHasExpiringToken(entry, cutoff) {
				continue
			}
			issuer, err := resolveIssuerForPrefix(ctx, discovery, entry.Prefix)
			if err != nil {
				log.Debugf("Skipping credential refresh for prefix %q: %v", entry.Prefix, err)
				continue
			}
			// Perform the (network) refreshes for this prefix in memory...
			n := 0
			for ti := range entry.Tokens {
				tok := &entry.Tokens[ti]
				if tok.RefreshToken == "" || time.Unix(tok.Expiration, 0).After(cutoff) {
					continue
				}
				if err := refreshTokenEntry(entry, tok, issuer); err != nil {
					log.Debugf("Failed to refresh a token for prefix %q: %v", entry.Prefix, err)
					continue
				}
				n++
			}
			if n == 0 {
				continue
			}
			// ...then persist this prefix under the credential file lock,
			// re-reading so concurrent changes to other prefixes are preserved.
			if err := config.UpsertPrefixEntry(discovery, entry); err != nil {
				log.Debugf("Failed to persist refreshed tokens for prefix %q: %v", entry.Prefix, err)
				continue
			}
			refreshed += n
		}
	}

	return refreshed, nil
}

// entryHasExpiringToken reports whether the entry has any refreshable token at
// or past the cutoff.
func entryHasExpiringToken(entry *config.PrefixEntry, cutoff time.Time) bool {
	for ti := range entry.Tokens {
		tok := &entry.Tokens[ti]
		if tok.RefreshToken != "" && !time.Unix(tok.Expiration, 0).After(cutoff) {
			return true
		}
	}
	return false
}

// resolveIssuerForPrefix determines the OAuth2 issuer URL for a stored
// credential. When the prefix is itself an issuer URL (a credential acquired
// directly from an issuer) it is returned as-is; otherwise the namespace
// prefix's issuer is resolved via a Director lookup in the federation
// identified by discovery.
func resolveIssuerForPrefix(ctx context.Context, discovery, prefix string) (string, error) {
	if strings.HasPrefix(prefix, "https://") || strings.HasPrefix(prefix, "http://") {
		return prefix, nil
	}

	discURL, err := url.Parse(discovery)
	if err != nil || discURL.Host == "" {
		return "", errors.Errorf("invalid federation discovery URL %q", discovery)
	}

	rp := "pelican://" + discURL.Host + "/" + strings.TrimPrefix(prefix, "/")
	pUrl, err := ParseRemoteAsPUrl(ctx, rp)
	if err != nil {
		return "", errors.Wrap(err, "failed to resolve federation information")
	}

	dirResp, err := getDirectorInfoForPath(ctx, pUrl, http.MethodGet, "", false)
	if err != nil {
		return "", errors.Wrap(err, "director lookup failed")
	}

	issuers := dirResp.XPelTokGenHdr.Issuers
	if len(issuers) == 0 {
		return "", errors.Errorf("director returned no issuer for prefix %q", prefix)
	}
	return issuers[0].String(), nil
}
