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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
)

const (
	// The issuer a client already holds a credential for, and the one the
	// object server actually accepts.  They differ so that a test can tell
	// whether the token hint changed which credential the client selected.
	wrongIssuer  = "https://issuer-the-client-already-had.example.com"
	hintedIssuer = "https://issuer.example.com"
)

// mintTestToken builds a WLCG token for the given issuer.  Signatures are never
// checked on this path -- tokenIsAcceptable parses claims with UnsafeParseClaims
// -- so a throwaway key is enough to produce a well-formed JWT.
func mintTestToken(t *testing.T, issuer string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject("test").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("scope", "storage.read:/").
		Claim("wlcg.ver", "1.0").
		Build()
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	require.NoError(t, err)
	return string(signed)
}

// writeTokenHintHeaders emits the X-Pelican-* headers a server that answers
// namespace questions about itself attaches to a response: which namespace the
// path belongs to, which issuers vouch for it, and how to obtain a credential.
func writeTokenHintHeaders(h http.Header) {
	ad := server_structs.NamespaceAd{
		Path: "/protected",
		Caps: server_structs.Capabilities{Reads: true},
	}
	issuer, _ := url.Parse(hintedIssuer)
	ad.Issuer = []server_structs.TokenIssuer{{IssuerUrl: *issuer, BasePaths: []string{"/protected"}}}
	ad.Generation = []server_structs.TokenGen{{
		Strategy:         server_structs.OAuthStrategy,
		MaxScopeDepth:    3,
		CredentialIssuer: *issuer,
	}}
	server_structs.SetXNamespaceHeader(h, nil, ad)
	server_structs.SetXAuthHeader(h, ad)
	server_structs.SetXTokenGenHeader(h, ad)
}

// tokenHintHandler simulates an origin that answers a client the way a director
// would.  It serves the object only to a caller presenting a token from
// hintedIssuer; anything else earns a 403 carrying the token hints that say so.
func tokenHintHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !presentsIssuer(r, hintedIssuer) {
			writeTokenHintHeaders(w.Header())
			w.WriteHeader(rejectionStatus(r))
			_, _ = w.Write([]byte("authorization required"))
			return
		}
		// Authorized: report size for HEAD (used to size the object), serve
		// the body for GET.
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	}
}

// presentsIssuer reports whether the request carries a bearer token minted by
// the given issuer.
func presentsIssuer(r *http.Request, issuer string) bool {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return false
	}
	tok, err := token.UnsafeParseClaims(strings.TrimPrefix(authz, "Bearer "))
	if err != nil {
		return false
	}
	return tok.Issuer() == issuer
}

// hintServerStats separates the two outcomes a test cares about.  Counting
// requests outright would be brittle: a completed download is followed by a
// checksum request, which now carries the credential the retry established.
type hintServerStats struct {
	rejected int32
	served   int32
}

// rejectionStatus mirrors what origin_serve answers a request it will not
// serve: 401 when the caller presented no credential at all -- the ordinary
// first request once nothing probes ahead of the transfer -- and 403 when one
// was presented and did not authorize.
func rejectionStatus(r *http.Request) int {
	if r.Header.Get("Authorization") == "" {
		return http.StatusUnauthorized
	}
	return http.StatusForbidden
}

// countingTokenHintHandler behaves like tokenHintHandler but records what it
// did, so a test can tell whether the attempt loop retried.
func countingTokenHintHandler(body string, stats *hintServerStats) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !presentsIssuer(r, hintedIssuer) {
			atomic.AddInt32(&stats.rejected, 1)
			writeTokenHintHeaders(w.Header())
			w.WriteHeader(rejectionStatus(r))
			_, _ = w.Write([]byte("authorization required"))
			return
		}
		atomic.AddInt32(&stats.served, 1)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	}
}

// hintTransferOpts describes the deployment a hint test is simulating.
type hintTransferOpts struct {
	// discoveryEndpoint overrides the federation's discovery host.  Left empty
	// it is the object server itself, which is what the user named.  Pointing
	// it elsewhere models reaching a host the client was sent to rather than
	// one the user chose -- a cache a director selected, say.
	discoveryEndpoint string
	// directorEndpoint, when set, gives the federation a director.  It must not
	// change whether a hint is honored; only who chose the host does.
	directorEndpoint string
}

// newHintTransfer builds a transferFile pointed at svrURL together with the
// job-wide token generator it shares, in the shape downloadObject expects.
func newHintTransfer(t *testing.T, svrURL string, opts hintTransferOpts) (*transferFile, *tokenGenerator) {
	t.Helper()
	parsed, err := url.Parse(svrURL)
	require.NoError(t, err)
	remoteURL := &pelican_url.PelicanURL{
		Scheme: "pelican://",
		Host:   parsed.Host,
		Path:   "/protected/test.txt",
	}
	remoteURL.FedInfo.DiscoveryEndpoint = svrURL
	if opts.discoveryEndpoint != "" {
		remoteURL.FedInfo.DiscoveryEndpoint = opts.discoveryEndpoint
	}
	remoteURL.FedInfo.DirectorEndpoint = opts.directorEndpoint
	tok := NewTokenGenerator(remoteURL, nil, config.TokenRead, false)
	tj := &TransferJob{remoteURL: remoteURL, token: tok}
	return &transferFile{
		ctx:       context.Background(),
		job:       tj,
		localPath: os.DevNull,
		remoteURL: parsed,
		token:     tok,
		attempts:  []transferAttemptDetails{{Url: parsed}},
		xferType:  transferTypeDownload,
	}, tok
}

// stageTwoCredentials puts two tokens where the client will discover them: one
// from an issuer the object server does not accept (found first), and one from
// the issuer it does.  Without a hint the client has no reason to prefer the
// second; the hint is what tells it which one is wanted.
func stageTwoCredentials(t *testing.T) {
	t.Helper()
	t.Setenv("BEARER_TOKEN", mintTestToken(t, wrongIssuer))
	good := filepath.Join(t.TempDir(), "good.jwt")
	require.NoError(t, os.WriteFile(good, []byte(mintTestToken(t, hintedIssuer)), 0o600))
	t.Setenv("BEARER_TOKEN_FILE", good)
	// Keep discovery from wandering into the invoking user's real credentials.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
}

// TestTokenHintAcquiresAndRetries is the positive case the whole mechanism
// exists for: a federation with no director, an object server that rejects the
// credential the client picked on its own, and a hint that names the one it
// actually wants.  The client must select the hinted credential and retry.
//
// Deleting the retry, or closing the gate that admits this hint, makes this
// test fail -- which is what keeps its negative counterparts below honest.
func TestTokenHintAcquiresAndRetries(t *testing.T) {
	stageTwoCredentials(t)

	body := "hello standalone"
	var stats hintServerStats
	svr := httptest.NewServer(countingTokenHintHandler(body, &stats))
	t.Cleanup(svr.Close)

	transfer, tok := newHintTransfer(t, svr.URL, hintTransferOpts{})

	// The credential the client picks unaided is the one the server rejects.
	first, err := tok.Get()
	require.NoError(t, err)
	parsedFirst, err := token.UnsafeParseClaims(first)
	require.NoError(t, err)
	require.Equal(t, wrongIssuer, parsedFirst.Issuer(),
		"fixture is wrong if the client already prefers the accepted credential")

	res, err := downloadObject(transfer)
	require.NoError(t, err)
	require.NoError(t, res.Error, "the hinted credential should have completed the transfer")
	assert.Equal(t, int64(len(body)), res.TransferredBytes)

	assert.Equal(t, int32(1), atomic.LoadInt32(&stats.rejected),
		"exactly one attempt should have been rejected before the hint was acted on")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&stats.served), int32(1),
		"the retry carrying the hinted credential should have been served")

	// The accepted credential is published to the job's generator so sibling
	// files and the checksum request that follows do not re-acquire it.
	cached := tok.Token.Load()
	require.NotNil(t, cached, "the accepted credential must be cached on the shared generator")
	parsedCached, err := token.UnsafeParseClaims(cached.Contents)
	require.NoError(t, err)
	assert.Equal(t, hintedIssuer, parsedCached.Issuer())
}

// TestTokenHintHonoredWhenFederationHasADirector pins that the presence of a
// director is not what decides this.  What matters is who chose the host: this
// is still the host from the user's own URL, so its hint is still worth acting
// on, director or no director.  The fixture is TestTokenHintAcquiresAndRetries
// plus a director endpoint, so an outcome that differs would mean the gate is
// keyed on the wrong thing.
func TestTokenHintHonoredWhenFederationHasADirector(t *testing.T) {
	stageTwoCredentials(t)

	body := "hello standalone"
	var stats hintServerStats
	svr := httptest.NewServer(countingTokenHintHandler(body, &stats))
	t.Cleanup(svr.Close)

	transfer, _ := newHintTransfer(t, svr.URL, hintTransferOpts{
		directorEndpoint: "https://director.example.com",
	})

	res, err := downloadObject(transfer)
	require.NoError(t, err)
	require.NoError(t, res.Error, "the hinted credential should have completed the transfer")
	assert.Equal(t, int64(len(body)), res.TransferredBytes)
	assert.Equal(t, int32(1), atomic.LoadInt32(&stats.rejected))
}

// TestTokenHintIgnoredFromHostTheUserDidNotName is the security boundary for the
// mechanism.  A hint feeds credential acquisition -- AcquireToken, OAuth2
// dynamic client registration, the interactive device-code flow -- so honoring
// one from the wrong party lets that party point a token request, or a login
// prompt shown to the user, at an issuer it chose.
//
// The client may take that advice only from a host its user named.  Here the
// endpoint serving the object is not the host in the pelican:// URL: it stands
// for somewhere the client was sent, a cache a director selected.  Its hint
// must be refused however well-formed it is.
func TestTokenHintIgnoredFromHostTheUserDidNotName(t *testing.T) {
	stageTwoCredentials(t)

	var stats hintServerStats
	svr := httptest.NewServer(countingTokenHintHandler("hello standalone", &stats))
	t.Cleanup(svr.Close)

	// Same server, but the host the user named is somewhere else.
	transfer, _ := newHintTransfer(t, svr.URL, hintTransferOpts{
		discoveryEndpoint: "https://the-host-the-user-named.example.com",
	})

	res, err := downloadObject(transfer)
	require.NoError(t, err)
	require.Error(t, res.Error, "a hint from a host the user never named must not be acted on")
	assert.Equal(t, int32(1), atomic.LoadInt32(&stats.rejected), "client must not retry")
	assert.Equal(t, int32(0), atomic.LoadInt32(&stats.served))
}

// TestTokenHintDoesNotDisplaceExplicitToken pins that a caller who named a
// credential keeps it.  Acting on a hint here would swap a credential the user
// chose for one acquired from an issuer the server named.
func TestTokenHintDoesNotDisplaceExplicitToken(t *testing.T) {
	stageTwoCredentials(t)

	var stats hintServerStats
	svr := httptest.NewServer(countingTokenHintHandler("hello standalone", &stats))
	t.Cleanup(svr.Close)

	transfer, tok := newHintTransfer(t, svr.URL, hintTransferOpts{})
	tok.SetToken(mintTestToken(t, wrongIssuer))

	res, err := downloadObject(transfer)
	require.NoError(t, err)
	require.Error(t, res.Error)
	assert.Equal(t, int32(1), atomic.LoadInt32(&stats.rejected),
		"an explicitly supplied credential must not be replaced by a hinted one")
	assert.Equal(t, int32(0), atomic.LoadInt32(&stats.served))
}

// TestCanApplyTokenHint covers the gate's decision table directly, including the
// combinations the end-to-end tests above cannot reach cheaply.
func TestCanApplyTokenHint(t *testing.T) {
	objectServer, err := url.Parse("https://origin.example.com:8444")
	require.NoError(t, err)

	newGen := func() *tokenGenerator {
		pUrl := &pelican_url.PelicanURL{Host: "origin.example.com:8444", Path: "/protected/obj"}
		pUrl.FedInfo.DiscoveryEndpoint = "https://origin.example.com:8444"
		return NewTokenGenerator(pUrl, nil, config.TokenRead, false)
	}

	t.Run("host-the-user-named", func(t *testing.T) {
		assert.True(t, newGen().canApplyTokenHint(objectServer))
	})

	t.Run("host-the-user-named-in-a-federation-with-a-director", func(t *testing.T) {
		tg := newGen()
		tg.Destination.FedInfo.DirectorEndpoint = "https://director.example.com"
		tg.SetDirectorResponse(&server_structs.DirectorResponse{})
		assert.True(t, tg.canApplyTokenHint(objectServer),
			"a director elsewhere does not unname the host the user typed")
	})

	t.Run("nil-generator", func(t *testing.T) {
		var tg *tokenGenerator
		assert.False(t, tg.canApplyTokenHint(objectServer))
	})

	t.Run("explicit-token", func(t *testing.T) {
		tg := newGen()
		tg.SetToken("chosen-by-the-caller")
		assert.False(t, tg.canApplyTokenHint(objectServer))
	})

	t.Run("external-provider", func(t *testing.T) {
		tg := newGen()
		tg.SetExternalProvider(StaticTokenProvider("from-elsewhere"))
		assert.False(t, tg.canApplyTokenHint(objectServer))
	})

	t.Run("different-host", func(t *testing.T) {
		other, err := url.Parse("https://cache.example.com:8443")
		require.NoError(t, err)
		assert.False(t, newGen().canApplyTokenHint(other))
	})

	t.Run("scheme-downgrade", func(t *testing.T) {
		plaintext, err := url.Parse("http://origin.example.com:8444")
		require.NoError(t, err)
		assert.False(t, newGen().canApplyTokenHint(plaintext),
			"a plaintext endpoint must not answer for an https discovery host")
	})

	t.Run("no-discovery-endpoint", func(t *testing.T) {
		tg := NewTokenGenerator(&pelican_url.PelicanURL{Path: "/protected/obj"}, nil, config.TokenRead, false)
		assert.False(t, tg.canApplyTokenHint(objectServer))
	})

	t.Run("nil-destination", func(t *testing.T) {
		assert.False(t, NewTokenGenerator(nil, nil, config.TokenRead, false).canApplyTokenHint(objectServer))
	})
}

// TestTokenHintKeyIsOrderIndependent pins that the same hint produces one key
// however the server happened to order its issuers.  Two orderings hashing
// apart would leave tokenForHint coalescing nothing, and a recursive job would
// acquire -- and prompt -- once per worker.
func TestTokenHintKeyIsOrderIndependent(t *testing.T) {
	issuer := func(host string) *url.URL {
		u, err := url.Parse(host)
		require.NoError(t, err)
		return u
	}
	a, b, c := issuer("https://a.example.com"), issuer("https://b.example.com"), issuer("https://c.example.com")

	hint := func(namespace string, issuers ...*url.URL) *server_structs.DirectorResponse {
		return &server_structs.DirectorResponse{
			XPelNsHdr:     server_structs.XPelNs{Namespace: namespace},
			XPelTokGenHdr: server_structs.XPelTokGen{Issuers: issuers},
		}
	}

	assert.Equal(t, tokenHintKey(hint("/protected", a, b)), tokenHintKey(hint("/protected", b, a)),
		"issuer order must not change the key")

	// Still discriminating: a different set, or a different namespace, is a
	// different question and must not be coalesced with this one.
	assert.NotEqual(t, tokenHintKey(hint("/protected", a, b)), tokenHintKey(hint("/protected", a, c)))
	assert.NotEqual(t, tokenHintKey(hint("/protected", a, b)), tokenHintKey(hint("/other", a, b)))

	// A nil entry is skipped rather than panicking or shifting the key.
	assert.Equal(t, tokenHintKey(hint("/protected", a)), tokenHintKey(hint("/protected", nil, a)))
}

// TestWithTokenHintIsolatesState verifies the generator returned for a hint
// carries the caller's token-selection settings but none of the receiver's
// mutable state, so acquiring a hinted credential cannot disturb sibling files.
func TestWithTokenHintIsolatesState(t *testing.T) {
	issuer, err := url.Parse(hintedIssuer)
	require.NoError(t, err)
	hint := server_structs.DirectorResponse{
		XPelNsHdr:     server_structs.XPelNs{Namespace: "/protected", RequireToken: true},
		XPelTokGenHdr: server_structs.XPelTokGen{Issuers: []*url.URL{issuer}},
	}

	base := NewTokenGenerator(nil, nil, config.TokenRead, true)
	base.SetTokenLocation("/tmp/some-token")
	base.SetTokenName("named")
	base.SetToken("cached-token-contents")

	derived := base.withTokenHint(&hint)

	assert.Equal(t, &hint, derived.DirResp)
	assert.Equal(t, "/tmp/some-token", derived.TokenLocation, "explicit token location must carry over")
	assert.Equal(t, config.TokenRead, derived.Operation)
	assert.Empty(t, derived.TokenName,
		"TokenName is assigned inside the receiver's singleflight; copying it would race with sibling workers")
	assert.Nil(t, derived.Token.Load(), "the derived generator must acquire fresh, not reuse the rejected token")
	assert.NotSame(t, base.Sync, derived.Sync, "the derived generator must not share singleflight state")

	// The receiver is untouched.
	assert.Nil(t, base.DirResp)
	require.NotNil(t, base.Token.Load())
	assert.Equal(t, "cached-token-contents", base.Token.Load().Contents)
}

// TestWithTokenHintConcurrentWithGet is a regression test for a data race:
// withTokenHint used to copy TokenName out of the receiver while sibling workers
// were inside getToken assigning it.  Meaningful under -race.
func TestWithTokenHintConcurrentWithGet(t *testing.T) {
	t.Setenv("BEARER_TOKEN", mintTestToken(t, hintedIssuer))
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	pUrl := &pelican_url.PelicanURL{Host: "origin.example.com", Path: "/protected/obj"}
	pUrl.FedInfo.DiscoveryEndpoint = "https://origin.example.com"
	base := NewTokenGenerator(pUrl, nil, config.TokenRead, false)
	hint := &server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{Namespace: "/protected", RequireToken: true},
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				// Force re-entry into getToken rather than the cached path.
				base.Token.Store(nil)
				_, _ = base.Get()
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = base.withTokenHint(hint)
			}
		}()
	}
	wg.Wait()
}

// TestDownloadHTTPYieldsTokenHint verifies that a rejection carrying X-Pelican
// token-hint headers is surfaced as a tokenHintError whose parsed
// DirectorResponse indicates a token is required -- the signal the attempt loop
// uses to acquire a credential and retry the same endpoint.
//
// Both rejection codes have to work.  With nothing probing ahead of the
// transfer, the ordinary first request carries no credential and earns a 401;
// 403 is what a presented-but-insufficient one earns.
func TestDownloadHTTPYieldsTokenHint(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{name: "no-credential-earns-401", token: ""},
		{name: "rejected-credential-earns-403", token: "not-a-jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svr := httptest.NewServer(tokenHintHandler("hello standalone"))
			t.Cleanup(svr.Close)

			transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
			require.NotEmpty(t, transfers)

			fname := filepath.Join(t.TempDir(), "out.txt")
			writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
			require.NoError(t, err)
			defer writer.Close()

			_, _, _, _, _, err = downloadHTTP(context.Background(), nil, nil, transfers[0], fname, writer, 0, -1, -1, tc.token, "", nil, nil)
			require.Error(t, err)

			var hintErr *tokenHintError
			require.True(t, errors.As(err, &hintErr), "expected a tokenHintError, got %T: %v", err, err)
			assert.True(t, hintErr.dirResp.XPelNsHdr.RequireToken)
			assert.Equal(t, "/protected", hintErr.dirResp.XPelNsHdr.Namespace)
			require.Len(t, hintErr.dirResp.XPelAuthHdr.Issuers, 1)
			assert.Equal(t, hintedIssuer, hintErr.dirResp.XPelAuthHdr.Issuers[0].String())
		})
	}
}

// TestDownloadHTTP_403NoHintIsTerminal verifies that a plain 403 (no X-Pelican
// headers) keeps the existing terminal authorization-error behavior and does NOT
// produce a tokenHintError.
func TestDownloadHTTP_403NoHintIsTerminal(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope"))
	}))
	t.Cleanup(svr.Close)

	transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
	require.NotEmpty(t, transfers)

	fname := filepath.Join(t.TempDir(), "out.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	_, _, _, _, _, err = downloadHTTP(context.Background(), nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil, nil)
	require.Error(t, err)

	var hintErr *tokenHintError
	assert.False(t, errors.As(err, &hintErr), "plain 403 must not be a tokenHintError")
}

// TestDownloadHTTP_SucceedsWithToken verifies the endpoint serves the object once
// an acceptable bearer token is supplied (the retry path's second attempt).
func TestDownloadHTTP_SucceedsWithToken(t *testing.T) {
	body := "hello standalone"
	svr := httptest.NewServer(tokenHintHandler(body))
	t.Cleanup(svr.Close)

	transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
	require.NotEmpty(t, transfers)

	fname := filepath.Join(t.TempDir(), "out.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	downloaded, _, _, _, _, err := downloadHTTP(context.Background(), nil, nil, transfers[0], fname, writer, 0, -1, -1, mintTestToken(t, hintedIssuer), "", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(len(body)), downloaded)
}

// TestResolveWithoutDirector covers how a client addresses an object when the
// federation's discovery document names no director.  It costs no round trip:
// the only possible object server is the discovery host the user already named,
// and what credential the namespace wants is left for the origin to say on the
// response that turns the request down.
func TestResolveWithoutDirector(t *testing.T) {
	pUrl := &pelican_url.PelicanURL{Path: "/protected/obj.txt"}
	pUrl.FedInfo.DiscoveryEndpoint = "https://origin.example.com:8444"

	resp, err := resolveWithoutDirector(pUrl)
	require.NoError(t, err)

	require.Len(t, resp.ObjectServers, 1)
	assert.Equal(t, "https://origin.example.com:8444", resp.ObjectServers[0].String())

	// An origin serving its own namespace is its own listing endpoint, which a
	// recursive transfer needs before it starts.
	require.NotNil(t, resp.XPelNsHdr.CollectionsUrl)
	assert.Equal(t, "https://origin.example.com:8444", resp.XPelNsHdr.CollectionsUrl.String())

	// Not guessed: the origin is about to say.
	assert.Empty(t, resp.XPelNsHdr.Namespace)
	assert.False(t, resp.XPelNsHdr.RequireToken)
	assert.Empty(t, resp.XPelAuthHdr.Issuers)
}

// TestResolveWithoutDirectorCostsNoRoundTrip is the point of resolving locally:
// a transfer against a directorless federation must not pay for a metadata
// request before it starts.  The download itself asks the only question that
// was ever outstanding, and the origin answers it on the way past.
func TestResolveWithoutDirectorCostsNoRoundTrip(t *testing.T) {
	var hits int32
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeTokenHintHeaders(w.Header())
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(svr.Close)

	pUrl := &pelican_url.PelicanURL{Path: "/protected/obj.txt"}
	pUrl.FedInfo.DiscoveryEndpoint = svr.URL

	resp, err := resolveWithoutDirector(pUrl)
	require.NoError(t, err)
	require.Len(t, resp.ObjectServers, 1)
	assert.Equal(t, svr.URL, resp.ObjectServers[0].String())

	assert.Equal(t, int32(0), atomic.LoadInt32(&hits),
		"resolving a download against a directorless federation must contact nobody")

	// The counterpart: a caller that cannot learn from a rejected response --
	// `token create`, a listing, a stat -- still asks, and gets real metadata.
	_, err = getDirectorInfoForPath(context.Background(), pUrl, http.MethodGet, "", false)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits),
		"callers that need the answer up front still pay for it")
}

func TestResolveWithoutDirectorRejectsUnparsableDiscoveryEndpoint(t *testing.T) {
	pUrl := &pelican_url.PelicanURL{Path: "/protected/obj.txt"}
	pUrl.FedInfo.DiscoveryEndpoint = "://not-a-url"

	_, err := resolveWithoutDirector(pUrl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discovery endpoint")
}

// TestGetDirectorInfoNoDirectorNoDiscovery keeps the original error for a URL
// carrying neither a director nor a discovery endpoint -- there is nothing to
// ask, and silently succeeding would strand the transfer later.
func TestGetDirectorInfoNoDirectorNoDiscovery(t *testing.T) {
	pUrl := &pelican_url.PelicanURL{Path: "/protected/obj.txt"}
	_, err := getDirectorInfoForPath(context.Background(), pUrl, http.MethodGet, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "none was found in pelican URL metadata")
}

// TestSetTokenEmptyDoesNotClaimExplicit keeps WithToken("") -- which several
// option paths pass through unconditionally -- from being mistaken for a caller
// naming a credential, which would silently disable token hints.
func TestSetTokenEmptyDoesNotClaimExplicit(t *testing.T) {
	objectServer, err := url.Parse("https://origin.example.com:8444")
	require.NoError(t, err)
	pUrl := &pelican_url.PelicanURL{Host: "origin.example.com:8444", Path: "/protected/obj"}
	pUrl.FedInfo.DiscoveryEndpoint = "https://origin.example.com:8444"

	tg := NewTokenGenerator(pUrl, nil, config.TokenRead, false)
	tg.SetToken("")
	assert.True(t, tg.canApplyTokenHint(objectServer))

	tg.SetToken("an-actual-credential")
	assert.False(t, tg.canApplyTokenHint(objectServer))
}
