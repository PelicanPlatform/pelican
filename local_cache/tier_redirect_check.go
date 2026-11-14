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

package local_cache

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// A redirect hands a client a URL the cache never fetches itself, so a URL
// that does not work -- because the cache's model of the storage service is
// wrong, its credential cannot be turned into a signed URL, or the URL's
// credential has run out -- would otherwise surface only as clients failing.
// So before handing any out, and again every liveness probe, the cache mints
// a URL for the target's identity object and fetches it exactly as a client
// would: with no credential but the URL's own.  Only while that works are
// clients redirected; otherwise they are proxied, which needs nothing but the
// cache's own credential.

// redirectUsable reports whether clients may be redirected to this target
// right now: it can mint URLs, and the latest self-test fetched one.
func (t *tierTarget) redirectUsable() bool {
	return t.canRedirect && t.redirectWorks.Load()
}

// checkRedirect runs the self-test and records the verdict: in redirectWorks,
// in the redirect-capable gauge, in the health component (see publishHealth),
// and -- only when the verdict changes -- in the log.
//
// Nothing is tested while Cache.TieringDisableRedirect is set: no client is
// redirected, so a URL that would not work concerns nobody.
func (t *tierTarget) checkRedirect(ctx context.Context) error {
	if !t.canRedirect || param.Cache_TieringDisableRedirect.GetBool() {
		tierRedirectCapable.WithLabelValues(t.metricLabel()).Set(0)
		return nil
	}
	err := t.redirectSelfTest(ctx)
	first := !t.redirectChecked.Swap(true)
	worked := t.redirectWorks.Swap(err == nil)
	if err != nil {
		t.lastRedirectError.Store(err.Error())
		tierRedirectCapable.WithLabelValues(t.metricLabel()).Set(0)
		if first || worked {
			log.Warnf("Redirect URLs for cache tier target %s do not work (%v); its objects will be proxied "+
				"through the cache until they do", t.DisplayURL(), err)
		}
		return err
	}
	t.lastRedirectError.Store("")
	tierRedirectCapable.WithLabelValues(t.metricLabel()).Set(1)
	if !first && !worked {
		log.Infof("Redirect URLs for cache tier target %s work again; clients will be redirected to it", t.DisplayURL())
	}
	return nil
}

// redirectSelfTest fetches the identity object through a freshly minted URL,
// with the lifetime real redirects get, and checks it returns the identity.
func (t *tierTarget) redirectSelfTest(ctx context.Context) error {
	redirector, ok := t.backend.(TierRedirector)
	if !ok {
		return errors.New("the backend cannot issue redirect URLs")
	}
	if t.redirectScheme != "http" && t.redirectScheme != "https" {
		// A file:// URL names storage the client shares with the target,
		// which the cache cannot stand in for; there is nothing to fetch.
		return nil
	}
	if t.identity == "" {
		return errors.New("the target's identity is not known yet")
	}
	ctx, cancel := context.WithTimeout(ctx, tierProbeTimeout)
	defer cancel()

	minted, err := redirector.RedirectURL(ctx, tierIdentityKey, tierRedirectExpiry(), nil)
	if err != nil {
		return err
	}
	// The URL carries a credential, so neither it nor an error quoting it
	// may reach the log; only its destination is described.
	dst, err := url.Parse(minted)
	if err != nil || !strings.EqualFold(dst.Scheme, t.redirectScheme) || !strings.EqualFold(dst.Host, t.redirectHost) {
		return errors.New("the backend minted a URL for a different destination than it reported at startup")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, minted, nil)
	if err != nil {
		return errors.New("the backend minted an unusable URL")
	}
	// A client follows the redirects the storage sends (a dCache door to a
	// pool, say), and so does this.
	client := &http.Client{Transport: config.GetTransport()}
	resp, err := client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return errors.Wrapf(err, "fetching a minted URL from %s failed", dst.Host)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("%s answered a minted URL with %s", dst.Host, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return errors.Wrapf(err, "reading a minted URL from %s failed", dst.Host)
	}
	if strings.TrimSpace(string(body)) != t.identity {
		return errors.Errorf("%s answered a minted URL with something other than the target's identity object", dst.Host)
	}
	return nil
}
