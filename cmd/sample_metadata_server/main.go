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
// What it verifies, in order:
//
//  1. There is an `Authorization: Bearer <jwt>` header.
//  2. The JWT is signed by the issuer named in its own `iss` claim. The
//     issuer's public keys are discovered via
//     `<iss>/.well-known/openid-configuration` → `jwks_uri`, then fetched and
//     cached (auto-refreshed). This is the same JWKS the origin publishes at
//     `/.well-known/issuer.jwks`.
//  3. The token is unexpired (with a small clock skew allowance).
//  4. The `aud` claim contains this receiver's audience (the URL the origin was
//     configured to POST to). Defends against token replay against a different
//     endpoint.
//  5. The `scope` claim carries `pelican.metadata`, and — when
//     -require-namespace-scope is set — a `pelican.metadata:/<ns>` scope whose
//     path covers the event's `namespace`. This is what stops an origin with a
//     token for namespace /A from publishing events it claims are for /B.
//
// Only after all of that does it parse the body (plain JSON, or the
// multipart/related shape used when an opaque metadata blob is attached) and
// print the event. A 2xx is returned on success; 401 for missing/bad tokens,
// 403 for a valid token that lacks the required scope.
//
// This is a REFERENCE implementation: it favors clarity over throughput and
// logs generously. It is not meant to be the production metadata sink.
//
// Example:
//
//	go run ./cmd/sample_metadata_server \
//	    -addr :9999 \
//	    -audience https://receiver.example.org:9999/events \
//	    -require-namespace-scope
//
// then point an origin at it:
//
//	Origin.Metadata.Enabled: true
//	Origin.Metadata.Endpoint: https://receiver.example.org:9999/events
//
// In a dev federation the origin's issuer usually presents a certificate signed
// by Pelican's per-federation CA. Pass -ca /path/to/ca.pem so the JWKS fetch
// trusts it.
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
	requireNamespace bool
	skew             time.Duration
	httpClient       *http.Client
}

func main() {
	var (
		addr             = flag.String("addr", ":9999", "address:port to listen on (use :0 to let the OS pick a free port)")
		path             = flag.String("path", "/", "request path that accepts the webhook POST")
		audience         = flag.String("audience", "", "expected token audience (this receiver's public URL). If empty, the audience check is skipped and a warning is logged.")
		requireNamespace = flag.Bool("require-namespace-scope", false, "require the token's pelican.metadata scope to carry a path covering the event's namespace")
		skew             = flag.Duration("clock-skew", 2*time.Minute, "acceptable clock skew when validating exp/nbf")
		caFile           = flag.String("ca", "", "PEM file of extra CA(s) to trust when fetching the issuer JWKS (e.g. a dev federation CA). In a dev federation, point this at the federation CA rather than disabling verification.")
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
		requireNamespace: *requireNamespace,
		skew:             *skew,
		httpClient:       client,
	}
	if cfg.audience == "" {
		log.Printf("WARNING: -audience is empty; the token audience will NOT be checked. Set it to this receiver's public URL in production.")
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
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	Namespace string                 `json:"namespace"`
	Object    map[string]interface{} `json:"object"`
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
		claims, err := v.verify(r.Context(), r.Header.Get("Authorization"), c.audience, c.skew)
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

// verifier caches issuer JWKS sets so repeated requests from the same origin
// don't re-fetch on every publish.
type verifier struct {
	client *http.Client

	mu     sync.Mutex
	caches map[string]*jwk.Cache // keyed by jwks_uri
}

func newVerifier(client *http.Client) *verifier {
	return &verifier{client: client, caches: map[string]*jwk.Cache{}}
}

// verifiedClaims is the subset of claims the handler needs after a token checks
// out.
type verifiedClaims struct {
	issuer string
	jti    string
	scopes []string
}

// verify parses and validates the bearer token from the Authorization header.
func (v *verifier) verify(ctx context.Context, authHeader, audience string, skew time.Duration) (*verifiedClaims, error) {
	raw, err := bearerToken(authHeader)
	if err != nil {
		return nil, err
	}

	// First pass: parse WITHOUT verification just to learn the issuer, so we
	// know whose JWKS to fetch. Nothing from this pass is trusted beyond the
	// issuer URL used for discovery.
	unverified, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	issuer := unverified.Issuer()
	if issuer == "" {
		return nil, fmt.Errorf("token has no issuer claim")
	}

	keySet, err := v.keySetFor(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer keys: %w", err)
	}

	opts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(skew),
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	tok, err := jwt.Parse([]byte(raw), opts...)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	return &verifiedClaims{issuer: tok.Issuer(), jti: tok.JwtID(), scopes: extractScopes(tok)}, nil
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

// keySetFor returns a (cached, auto-refreshing) jwk.Set for the issuer.
func (v *verifier) keySetFor(ctx context.Context, issuer string) (jwk.Set, error) {
	jwksURI, err := v.discoverJWKS(ctx, issuer)
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	cache, ok := v.caches[jwksURI]
	if !ok {
		cache = jwk.NewCache(context.Background())
		if regErr := cache.Register(jwksURI, jwk.WithHTTPClient(v.client), jwk.WithMinRefreshInterval(15*time.Minute)); regErr != nil {
			v.mu.Unlock()
			return nil, fmt.Errorf("register jwks cache: %w", regErr)
		}
		v.caches[jwksURI] = cache
	}
	v.mu.Unlock()

	set, err := cache.Get(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %s: %w", jwksURI, err)
	}
	return set, nil
}

// discoverJWKS resolves the issuer's jwks_uri via OIDC discovery.
func (v *verifier) discoverJWKS(ctx context.Context, issuer string) (string, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", discoveryURL, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery %s returned %d", discoveryURL, resp.StatusCode)
	}
	var doc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode discovery doc: %w", err)
	}
	if doc.JwksURI == "" {
		return "", fmt.Errorf("discovery doc for %s has no jwks_uri", issuer)
	}
	return doc.JwksURI, nil
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
