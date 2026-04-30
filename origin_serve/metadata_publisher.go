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

// File metadata_publisher.go owns:
//   - Building the publish HTTP request (URL/headers/body) from an event.
//   - Minting the bearer JWT (`pelican.metadata:/<ns>` scope).
//   - Performing one publish attempt against an endpoint URL with a
//     configurable per-attempt timeout.
//
// It is intentionally stateless beyond the HTTP client: both the
// transactional path and the eventually-consistent worker call into
// the same Attempt() helper.

package origin_serve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// publishOutcome is one of the outcome labels used in metrics. It is
// also returned to the caller so transactional mode knows whether to
// roll back.
type publishOutcome string

const (
	outcomeSuccess publishOutcome = "success"
	outcomeHTTP4xx publishOutcome = "http_4xx"
	outcomeHTTP5xx publishOutcome = "http_5xx"
	outcomeNetwork publishOutcome = "network"
	outcomeTimeout publishOutcome = "timeout"
)

// publishResult bundles the outcome of one attempt.
type publishResult struct {
	outcome publishOutcome
	status  int
	err     error
}

// IsSuccess reports whether the attempt counts as a successful publish.
func (r publishResult) IsSuccess() bool { return r.outcome == outcomeSuccess }

// IdempotencyKeyHeader is the header that carries the event UUID on
// the outgoing webhook request. The well-known `Idempotency-Key`
// header is still an IETF draft (draft-ietf-httpapi-idempotency-key);
// per Pelican convention any non-RFC header is namespaced with the
// `X-Pelican-` prefix so receivers can tell at a glance which header
// belongs to Pelican vs the broader HTTP ecosystem. If the IETF
// promotes the bare name to an RFC, we'll add an alias.
const IdempotencyKeyHeader = "X-Pelican-Idempotency-Key"

// publisher owns the HTTP client + token-mint policy used by both modes.
// Hooks let tests inject a deterministic token signer / clock.
type publisher struct {
	client         *http.Client
	tokenLifetime  time.Duration
	requestTimeout time.Duration

	// signToken is overridable in tests. Production wiring uses
	// config.GetIssuerPrivateJWK() under the hood.
	signToken func(audience, namespace string) (string, error)

	// userAgent is the User-Agent we send.
	userAgent string

	clock func() time.Time
}

// newPublisher builds a publisher with sensible defaults. Wire-up of
// the signer / metrics hooks happens in Initialize().
//
// The HTTP client is the Pelican-managed singleton from `config`,
// which gives us connection pooling, our custom CA roots, the
// broker-aware dialer, and proxy / redirect policy consistent with
// the rest of the Pelican daemon. Per-attempt timeouts are enforced
// via context deadlines inside Attempt(), so we do *not* set the
// global Client.Timeout.
func newPublisher(reqTimeout, tokenLifetime time.Duration) *publisher {
	return &publisher{
		client:         config.GetClient(),
		tokenLifetime:  tokenLifetime,
		requestTimeout: reqTimeout,
		signToken:      defaultSignToken(tokenLifetime),
		userAgent:      "pelican-origin-metadata/1",
		clock:          time.Now,
	}
}

// defaultSignToken returns a signer that mints a fresh
// `pelican.metadata:/<ns>` JWT for each attempt. The function captures
// the configured token lifetime at construction time.
func defaultSignToken(lifetime time.Duration) func(audience, namespace string) (string, error) {
	return func(audience, namespace string) (string, error) {
		issuerURL, err := config.GetServerIssuerURL()
		if err != nil {
			return "", fmt.Errorf("metadata publisher: get issuer url: %w", err)
		}
		cfg := token.NewWLCGToken()
		cfg.Lifetime = lifetime
		cfg.Issuer = issuerURL
		cfg.Subject = issuerURL
		if audience != "" {
			cfg.AddAudiences(audience)
		}
		scope := token_scopes.Pelican_Metadata
		if namespace != "" {
			ns := namespace
			if !strings.HasPrefix(ns, "/") {
				ns = "/" + ns
			}
			scoped, err := scope.Path(ns)
			if err == nil {
				scope = scoped
			}
		}
		cfg.AddScopes(scope)
		return cfg.CreateToken()
	}
}

// Attempt performs one publish to `endpoint` for `event`. The supplied
// ctx bounds the entire request (including the timeout). The body is
// the JSON-marshalled event; the bearer JWT is minted just-in-time.
func (p *publisher) Attempt(ctx context.Context, endpoint string, event *ObjectCommitEvent) publishResult {
	if endpoint == "" {
		return publishResult{outcome: outcomeNetwork, err: errors.New("metadata publisher: endpoint is empty")}
	}

	body, err := event.MarshalJSON()
	if err != nil {
		return publishResult{outcome: outcomeNetwork, err: fmt.Errorf("marshal event: %w", err)}
	}

	tokenStr, err := p.signToken(endpoint, event.Namespace)
	if err != nil {
		return publishResult{outcome: outcomeNetwork, err: fmt.Errorf("mint token: %w", err)}
	}

	attemptCtx, cancel := context.WithTimeout(ctx, p.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return publishResult{outcome: outcomeNetwork, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	// Non-RFC headers are namespaced with the X-Pelican- prefix per
	// project convention. Idempotency-Key is still an IETF draft as
	// of this writing; the canonical name is exported as
	// IdempotencyKeyHeader so callers can refer to it.
	req.Header.Set(IdempotencyKeyHeader, event.ID)
	req.Header.Set("User-Agent", p.userAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return publishResult{outcome: outcomeTimeout, err: err}
		}
		return publishResult{outcome: outcomeNetwork, err: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return publishResult{outcome: outcomeSuccess, status: resp.StatusCode}
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		log.Warnf("metadata endpoint returned 4xx for event %s ns=%s: %d", event.ID, event.Namespace, resp.StatusCode)
		return publishResult{outcome: outcomeHTTP4xx, status: resp.StatusCode, err: fmt.Errorf("http %d", resp.StatusCode)}
	}
	return publishResult{outcome: outcomeHTTP5xx, status: resp.StatusCode, err: fmt.Errorf("http %d", resp.StatusCode)}
}
