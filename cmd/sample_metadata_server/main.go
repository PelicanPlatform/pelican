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

// Command sample_metadata_server is a reference receiver for the V2 origin's
// object-commit metadata webhook (see docs/v2-origin-posc-and-metadata.md). It
// exists so operators and developers can stand up a real endpoint that a
// standalone origin can publish to, and — crucially — it validates the bearer
// JWT the origin mints rather than blindly trusting the request body.
//
// How key discovery works (the important part for Pelican newcomers):
//
// The origin does NOT need to be reachable from this receiver. Each Pelican
// namespace registers the *public* half of its signing key with the
// federation's registry; the origin holds the private half and signs the
// webhook JWT with it. So to verify the token, the receiver:
//
//  1. reads the event body's `federation` and `namespace` (untrusted so far);
//  2. does federation discovery: GET
//     `<federation>/.well-known/pelican-configuration` and reads
//     `namespace_registration_endpoint` (the registry);
//  3. fetches that namespace's public keys from the registry:
//     `<registry>/api/v1.0/registry/<namespace>/.well-known/issuer.jwks`
//     (cached, auto-refreshed);
//  4. verifies the JWT signature against those keys.
//
// TRUST ANCHOR: `federation` and `iss` come from the unverified request, so
// the receiver NEVER fetches a URL taken from them. It is configured with the
// federation(s)/issuer(s) it trusts and only ever discovers keys from those
// configured values; the event's federation / token's issuer are merely
// compared against them to authorize the source. This is what prevents a
// forged event from pointing verification at an attacker-controlled host
// (SSRF). Configure at least one of:
//
//   - -federation <discovery-url>: registry-based. An event's `federation`
//     must equal this; keys come from this federation's registry.
//   - -issuer <url>: OIDC fallback for events that carry no `federation`. The
//     token's `iss` must equal this; keys come from this issuer's JWKS.
//
// With neither set, every event is rejected.
//
// After key discovery it also checks, in order:
//
//   - the token is unexpired (small clock-skew allowance);
//   - `aud` contains this receiver's audience (defends against replay against a
//     different endpoint);
//   - `scope` carries `pelican.metadata`, and — when -require-namespace-scope
//     is set — a `pelican.metadata:/<ns>` scope whose path covers the event's
//     `namespace` (stops a token for /A from publishing events claiming /B).
//
// Only then does it parse the body fully and print the event. 2xx on success;
// 401 for missing/bad tokens, 403 for a valid token lacking the required scope.
//
// This is a REFERENCE implementation: it favors clarity over throughput and
// logs generously. It is not meant to be the production metadata sink.
//
// Example:
//
//	go run ./cmd/sample_metadata_server \
//	    -addr :9999 \
//	    -audience https://receiver.example.org:9999/events \
//	    -federation osg-htc.org \
//	    -require-namespace-scope
//
// then point an origin at it:
//
//	Origin.Metadata.Enabled: true
//	Origin.Metadata.Endpoint: https://receiver.example.org:9999/events
//
// In a dev federation the registry usually presents a certificate signed by
// Pelican's per-federation CA. Pass -ca /path/to/ca.pem so the discovery /
// JWKS fetches trust it.
//
// When -addr uses port 0 (e.g. "127.0.0.1:0"), the OS picks a free port; the
// actual bound URL is printed to stdout on a line prefixed with
// listeningLinePrefix so a launching tool can discover it.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// metadataScope is the top-level scope the origin stamps on the webhook token.
// A scope entry is either the bare authority ("pelican.metadata") or
// authority-plus-path ("pelican.metadata:/foo").
const metadataScope = "pelican.metadata"

// listeningLinePrefix marks the stdout line that reports the actual bound URL.
// A caller that launched this server with an OS-assigned port (":0") scans
// stdout for this prefix to discover where to send requests.
const listeningLinePrefix = "SAMPLE_METADATA_SERVER_LISTENING "

// config holds the parsed command-line configuration.
type config struct {
	path             string
	audience         string
	federation       string // trusted federation discovery URL (canonical); registry-based verification
	issuer           string // trusted issuer URL (canonical); OIDC fallback for events without a federation
	requireNamespace bool
	skew             time.Duration
	httpClient       *http.Client
}

func main() {
	var (
		addr             = flag.String("addr", ":9999", "address:port to listen on (use :0 to let the OS pick a free port)")
		path             = flag.String("path", "/", "request path that accepts the webhook POST")
		audience         = flag.String("audience", "", "expected token audience (this receiver's public URL). If empty, the audience check is skipped and a warning is logged.")
		federation       = flag.String("federation", "", "federation discovery URL to TRUST for registry-based key discovery (e.g. osg-htc.org). An event's JWT is verified against THIS federation's registry; events claiming a different federation are rejected. Key discovery never fetches a URL taken from the (untrusted) event.")
		issuer           = flag.String("issuer", "", "issuer URL to TRUST for the OIDC fallback used by events that carry no federation. The token's iss must match this exactly; keys are fetched from this configured value, never the token's iss.")
		requireNamespace = flag.Bool("require-namespace-scope", false, "require the token's pelican.metadata scope to carry a path covering the event's namespace")
		skew             = flag.Duration("clock-skew", 2*time.Minute, "acceptable clock skew when validating exp/nbf")
		caFile           = flag.String("ca", "", "PEM file of extra CA(s) to trust when fetching federation discovery / registry JWKS (e.g. a dev federation CA). In a dev federation, point this at the federation CA rather than disabling verification.")
		tlsCert          = flag.String("tls-cert", "", "optional TLS certificate to serve HTTPS")
		tlsKey           = flag.String("tls-key", "", "optional TLS key to serve HTTPS")
	)
	flag.Parse()

	client, err := buildHTTPClient(*caFile)
	if err != nil {
		log.Fatalf("building HTTP client: %v", err)
	}

	cfg := &config{
		path:             *path,
		audience:         strings.TrimSpace(*audience),
		federation:       canonicalFederation(*federation),
		issuer:           canonicalFederation(*issuer),
		requireNamespace: *requireNamespace,
		skew:             *skew,
		httpClient:       client,
	}
	if cfg.audience == "" {
		log.Printf("WARNING: -audience is empty; the token audience will NOT be checked. Set it to this receiver's public URL in production.")
	}
	if cfg.federation == "" && cfg.issuer == "" {
		log.Printf("WARNING: neither -federation nor -issuer is set; this receiver has no trusted key source and will REJECT every event. Set -federation <discovery-url> (registry-based) and/or -issuer <url> (OIDC fallback).")
	}
	if !cfg.requireNamespace {
		log.Printf("WARNING: -require-namespace-scope is off; any token bearing the bare 'pelican.metadata' scope is accepted for ANY namespace. Enable it in production.")
	}

	v := newVerifier(client)
	mux := http.NewServeMux()
	mux.HandleFunc(cfg.path, cfg.makeHandler(v))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})

	serveTLS := *tlsCert != "" && *tlsKey != ""

	// Bind explicitly so that an OS-assigned port (":0") can be reported back.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", *addr, err)
	}
	scheme := "http"
	if serveTLS {
		scheme = "https"
	}
	baseURL := scheme + "://" + ln.Addr().String()
	// Machine-readable readiness line (stdout): a caller launched with ":0"
	// parses this to discover the port. The server is already bound at this
	// point, so the port in the URL is final.
	fmt.Printf("%s%s\n", listeningLinePrefix, baseURL)
	log.Printf("sample metadata receiver listening on %s (path %q, audience %q, require-namespace-scope=%v)",
		baseURL, cfg.path, cfg.audience, cfg.requireNamespace)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if serveTLS {
		err = srv.ServeTLS(ln, *tlsCert, *tlsKey)
	} else {
		err = srv.Serve(ln)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("server exited: %v", err)
	}
}

// buildHTTPClient returns an *http.Client whose transport trusts the system
// roots plus any CA in caFile. There is deliberately no "skip verification"
// escape hatch: an operator standing up a receiver against a dev federation
// should trust that federation's CA via -ca, not turn verification off.
func buildHTTPClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// objectCommitEvent mirrors the webhook JSON body. Custom uploader fields are
// inlined into the object map alongside the reserved keys, so object stays a
// free-form map.
type objectCommitEvent struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Timestamp  string                 `json:"timestamp"`
	Federation string                 `json:"federation"`
	Namespace  string                 `json:"namespace"`
	Object     map[string]interface{} `json:"object"`
}

// makeHandler returns the HTTP handler for the webhook path.
func (c *config) makeHandler(v *verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 8 MiB comfortably exceeds the origin's default 4 MiB metadata-part
		// limit.
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		event, blobInfo, err := parseBody(r.Header.Get("Content-Type"), body)
		if err != nil {
			log.Printf("reject: body parse: %v", err)
			http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
			return
		}

		// --- Token verification. This is the point of the sample. ---
		claims, err := v.verify(r.Context(), r.Header.Get("Authorization"), verifyRequest{
			trustedFederation: c.federation,
			trustedIssuer:     c.issuer,
			eventFederation:   event.Federation,
			namespace:         event.Namespace,
			audience:          c.audience,
			skew:              c.skew,
		})
		if err != nil {
			log.Printf("reject: token: %v", err)
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if err := checkScope(claims.scopes, event.Namespace, c.requireNamespace); err != nil {
			log.Printf("reject: scope: %v (scopes=%v)", err, claims.scopes)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}

		idemHeader := r.Header.Get("X-Pelican-Idempotency-Key")
		if idemHeader != "" && event.ID != "" && idemHeader != event.ID {
			log.Printf("warning: X-Pelican-Idempotency-Key %q != event id %q", idemHeader, event.ID)
		}

		log.Printf("ACCEPT event id=%s type=%s ns=%s path=%v issuer=%s jti=%s%s",
			event.ID, event.Type, event.Namespace, event.Object["path"], claims.issuer, claims.jti, blobInfo)

		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "accepted\n")
	}
}

// parseBody handles both wire shapes: plain application/json and the
// multipart/related body used when an opaque metadata blob rides along.
// blobInfo is a short human-readable suffix for the accept log.
func parseBody(contentType string, body []byte) (objectCommitEvent, string, error) {
	var event objectCommitEvent
	mediaType, params, _ := mime.ParseMediaType(contentType)

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return event, "", fmt.Errorf("multipart body missing boundary")
		}
		mr := multipart.NewReader(strings.NewReader(string(body)), boundary)
		var (
			gotRoot  bool
			blobType string
			blobLen  int
		)
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return event, "", fmt.Errorf("read multipart part: %w", err)
			}
			partBody, _ := io.ReadAll(part)
			if strings.Contains(part.Header.Get("Content-Type"), "application/json") && !gotRoot {
				if err := json.Unmarshal(partBody, &event); err != nil {
					return event, "", fmt.Errorf("unmarshal root json part: %w", err)
				}
				gotRoot = true
			} else {
				blobType = part.Header.Get("Content-Type")
				blobLen = len(partBody)
			}
			_ = part.Close()
		}
		if !gotRoot {
			return event, "", fmt.Errorf("multipart body had no application/json root part")
		}
		return event, fmt.Sprintf(" blob=%s(%d bytes)", blobType, blobLen), nil
	}

	if err := json.Unmarshal(body, &event); err != nil {
		return event, "", fmt.Errorf("unmarshal json: %w", err)
	}
	return event, "", nil
}

// verifier caches JWKS sets (keyed by JWKS URL) and resolved registry
// endpoints (keyed by federation) so repeated publishes don't re-discover on
// every request.
type verifier struct {
	client *http.Client

	mu       sync.Mutex
	caches   map[string]*jwk.Cache // keyed by jwks url
	registry map[string]string     // federation discovery url -> registry endpoint
}

func newVerifier(client *http.Client) *verifier {
	return &verifier{
		client:   client,
		caches:   map[string]*jwk.Cache{},
		registry: map[string]string{},
	}
}

// verifyRequest carries everything verify() needs. The trusted* fields come
// from this receiver's configuration (command line); the event*/namespace
// fields come from the still-untrusted request body. Key discovery only ever
// fetches from a trusted* value — the event's are compared against them, never
// fetched — so a forged event cannot point verification at a host the
// attacker controls (SSRF).
type verifyRequest struct {
	trustedFederation string // -federation (canonical); "" if not configured
	trustedIssuer     string // -issuer (canonical); "" if not configured
	eventFederation   string // federation the event claims (untrusted)
	namespace         string // namespace the event claims (untrusted)
	audience          string
	skew              time.Duration
}

// verifiedClaims is the subset of claims the handler needs after a token checks
// out.
type verifiedClaims struct {
	issuer string
	jti    string
	scopes []string
}

// verify validates the bearer token, discovering keys from a configured trust
// anchor (see discoverKeys). Registry-based discovery (via the event's
// federation) means the origin need not be reachable; the issuer-pinned path
// is the fallback for events that carry no federation.
func (v *verifier) verify(ctx context.Context, authHeader string, req verifyRequest) (*verifiedClaims, error) {
	raw, err := bearerToken(authHeader)
	if err != nil {
		return nil, err
	}

	// Parse WITHOUT verification, only to read the (untrusted) `iss` used to
	// select and match the configured issuer anchor. Nothing here is trusted.
	unverified, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}

	keySet, err := v.discoverKeys(ctx, req, unverified.Issuer())
	if err != nil {
		return nil, err
	}

	opts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(req.skew),
	}
	if req.audience != "" {
		opts = append(opts, jwt.WithAudience(req.audience))
	}
	tok, err := jwt.Parse([]byte(raw), opts...)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	return &verifiedClaims{issuer: tok.Issuer(), jti: tok.JwtID(), scopes: extractScopes(tok)}, nil
}

// discoverKeys returns the verification key set, fetching ONLY from this
// receiver's configured trust anchors (req.trustedFederation / req.trustedIssuer)
// — never from a URL taken out of the event body or the token. The event's
// federation and the token's issuer are compared against those anchors to
// authorize the source; they are never themselves fetched. This is what keeps
// a forged event from redirecting verification at an attacker-controlled host
// (SSRF / request forgery).
func (v *verifier) discoverKeys(ctx context.Context, req verifyRequest, tokenIssuer string) (jwk.Set, error) {
	// Registry-based: use it when this receiver trusts the federation the event
	// names, discovering from the *configured* value.
	if req.trustedFederation != "" && req.eventFederation != "" &&
		canonicalFederation(req.eventFederation) == req.trustedFederation {
		namespace, err := validateNamespace(req.namespace)
		if err != nil {
			return nil, err
		}
		return v.keySetForNamespace(ctx, req.trustedFederation, namespace)
	}

	// Issuer-pinned: use it when this receiver trusts the issuer the token
	// names (OIDC on the *configured* value). Covers events that carry no
	// federation, and is tried when the registry path above did not apply.
	if req.trustedIssuer != "" && tokenIssuer != "" &&
		canonicalFederation(tokenIssuer) == req.trustedIssuer {
		return v.keySetForIssuer(ctx, req.trustedIssuer)
	}

	// Neither anchor applied.
	if req.eventFederation != "" && req.trustedFederation != "" {
		return nil, fmt.Errorf("event federation %q is not the trusted federation %q, and token issuer %q does not match -issuer", req.eventFederation, req.trustedFederation, tokenIssuer)
	}
	return nil, fmt.Errorf("no trusted key source: no -federation matches the event's federation %q, and no -issuer matches the token issuer %q", req.eventFederation, tokenIssuer)
}

// validateNamespace rejects a namespace that could escape the registry path or
// inject a host before it is used to build the registry JWKS URL.
func validateNamespace(ns string) (string, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return "", fmt.Errorf("event has no namespace; cannot locate registry keys")
	}
	if !strings.HasPrefix(ns, "/") {
		return "", fmt.Errorf("namespace %q must start with '/'", ns)
	}
	if strings.Contains(ns, "..") || strings.Contains(ns, "://") || strings.ContainsAny(ns, " \t\r\n?#\\") {
		return "", fmt.Errorf("namespace %q contains disallowed characters", ns)
	}
	return ns, nil
}

// bearerToken pulls the raw JWT out of an Authorization header.
func bearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", fmt.Errorf("Authorization header is not a Bearer token")
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", fmt.Errorf("empty bearer token")
	}
	return tok, nil
}

// keySetForNamespace discovers a namespace's public keys via the federation
// registry: federation discovery -> registry endpoint -> namespace JWKS.
func (v *verifier) keySetForNamespace(ctx context.Context, federation, namespace string) (jwk.Set, error) {
	registry, err := v.registryEndpoint(ctx, federation)
	if err != nil {
		return nil, err
	}
	jwksURL, err := namespaceJWKSURL(registry, namespace)
	if err != nil {
		return nil, err
	}
	return v.keySetForURL(ctx, jwksURL)
}

// keySetForIssuer is the legacy path: resolve the issuer's jwks_uri via OIDC
// discovery on the token's `iss`. Requires reachability to the origin.
func (v *verifier) keySetForIssuer(ctx context.Context, issuer string) (jwk.Set, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	var doc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, discoveryURL, &doc); err != nil {
		return nil, err
	}
	if doc.JwksURI == "" {
		return nil, fmt.Errorf("openid-configuration for %s has no jwks_uri", issuer)
	}
	return v.keySetForURL(ctx, doc.JwksURI)
}

// registryEndpoint resolves (and caches) a federation's registry endpoint via
// federation discovery. `federation` must already be canonical (see
// canonicalFederation).
func (v *verifier) registryEndpoint(ctx context.Context, federation string) (string, error) {
	v.mu.Lock()
	if reg, ok := v.registry[federation]; ok {
		v.mu.Unlock()
		return reg, nil
	}
	v.mu.Unlock()

	discoveryURL := federation + "/.well-known/pelican-configuration"
	var doc struct {
		RegistryEndpoint string `json:"namespace_registration_endpoint"`
	}
	if err := v.getJSON(ctx, discoveryURL, &doc); err != nil {
		return "", fmt.Errorf("federation discovery: %w", err)
	}
	if doc.RegistryEndpoint == "" {
		return "", fmt.Errorf("federation discovery doc %s has no namespace_registration_endpoint", discoveryURL)
	}

	v.mu.Lock()
	v.registry[federation] = doc.RegistryEndpoint
	v.mu.Unlock()
	return doc.RegistryEndpoint, nil
}

// namespaceJWKSURL builds the registry URL that serves a namespace's public
// keys: <registry>/api/v1.0/registry/<namespace>/.well-known/issuer.jwks.
func namespaceJWKSURL(registry, namespace string) (string, error) {
	u, err := url.Parse(registry)
	if err != nil {
		return "", fmt.Errorf("parse registry endpoint %q: %w", registry, err)
	}
	// JoinPath cleans duplicate slashes, so a namespace like "/foo/bar" is
	// safely appended as path segments.
	u = u.JoinPath("api", "v1.0", "registry", namespace, ".well-known", "issuer.jwks")
	return u.String(), nil
}

// keySetForURL returns a cached, auto-refreshing jwk.Set for a JWKS URL.
func (v *verifier) keySetForURL(ctx context.Context, jwksURL string) (jwk.Set, error) {
	v.mu.Lock()
	cache, ok := v.caches[jwksURL]
	if !ok {
		cache = jwk.NewCache(context.Background())
		if regErr := cache.Register(jwksURL, jwk.WithHTTPClient(v.client), jwk.WithMinRefreshInterval(15*time.Minute)); regErr != nil {
			v.mu.Unlock()
			return nil, fmt.Errorf("register jwks cache: %w", regErr)
		}
		v.caches[jwksURL] = cache
	}
	v.mu.Unlock()

	set, err := cache.Get(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %s: %w", jwksURL, err)
	}
	return set, nil
}

// getJSON GETs reqURL and decodes a 200 JSON body into out.
func (v *verifier) getJSON(ctx context.Context, reqURL string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", reqURL, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned %d", reqURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", reqURL, err)
	}
	return nil
}

// canonicalFederation normalizes a federation discovery URL to a stable form
// so the pinned value and an event's value compare equal despite scheme /
// case / default-port / trailing-slash differences. A bare host is assumed
// https. Returns "" for empty input.
func canonicalFederation(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimRight(s, "/"))
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Scheme == "https" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	} else if u.Scheme == "http" {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// extractScopes reads the space-delimited `scope` claim into a slice. Tolerates
// a `scope` claim that arrives as a JSON array too.
func extractScopes(tok jwt.Token) []string {
	v, ok := tok.Get("scope")
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case string:
		return strings.Fields(s)
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

// checkScope enforces that the token authorizes a pelican.metadata publish and,
// when requireNamespace is set, that a scope path covers the event's namespace.
func checkScope(scopes []string, eventNamespace string, requireNamespace bool) error {
	var (
		sawMetadata bool
		nsCovered   bool
	)
	for _, s := range scopes {
		authority, scopePath := splitScope(s)
		if authority != metadataScope {
			continue
		}
		sawMetadata = true
		if scopePath != "" && pathCovers(scopePath, eventNamespace) {
			nsCovered = true
		}
	}
	if !sawMetadata {
		return fmt.Errorf("token lacks %s scope", metadataScope)
	}
	if requireNamespace && !nsCovered {
		return fmt.Errorf("no %s scope path covers event namespace %q", metadataScope, eventNamespace)
	}
	return nil
}

// splitScope splits "authority:/path" into ("authority", "/path").
func splitScope(scope string) (authority, path string) {
	if i := strings.IndexByte(scope, ':'); i >= 0 {
		return scope[:i], scope[i+1:]
	}
	return scope, ""
}

// pathCovers reports whether a scope path grants access to target. A scope for
// "/foo" covers "/foo" and "/foo/bar" but not "/foobar" or "/bar".
func pathCovers(scopePath, target string) bool {
	scopePath = "/" + strings.Trim(scopePath, "/")
	target = "/" + strings.Trim(target, "/")
	if scopePath == "/" {
		return true
	}
	if scopePath == target {
		return true
	}
	return strings.HasPrefix(target, scopePath+"/")
}
