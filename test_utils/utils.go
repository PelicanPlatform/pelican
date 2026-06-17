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

package test_utils

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/config/configtest"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

// === Server and client test initialization (primary API) ===
//
// InitServerForTest and InitClientForTest are the entry points most tests
// use. The Option constructors configure them; the unexported helpers near
// the end of this section implement the shared orchestration.

// InitServerForTest prepares an isolated server configuration and then
// calls config.InitServer. "Isolated" means an ambient
// /etc/pelican/pelican.yaml is shadowed and the embedded OSDF federation
// defaults are cleared, so the test sees only state it sets explicitly.
//
// Pass WithFederationMock or WithLazyFederationMock to stand up a CA-signed
// mock discovery endpoint. With neither, config.InitServer's
// ErrNoDiscoveryEndpoint is treated as a clean "no federation" state.
//
// Unlike InitClientForTest, this does NOT call config.ResetConfig: callers
// routinely stage overrides (OIDC client files, storage locations, ports,
// hostnames) beforehand, and resetting Viper here would discard them. Call
// server_utils.ResetTestState earlier in the test body when a clean slate
// is required.
func InitServerForTest(t testing.TB, ctx context.Context, serverType server_structs.ServerType, opts ...Option) {
	t.Helper()
	o := resolveOptions(opts)

	cfgDir := prepareConfigDir(t, o)

	InitServerTLSForTest(t, cfgDir)
	require.NoError(t, config.GenerateCert())

	applyInitCfg(t, "InitServerForTest", o.initCfg)

	if o.fedMode == federationEager {
		startFederationMock(t, o)
	}

	// With no mock discovery endpoint, treat "no federation" as success.
	err := config.InitServer(ctx, serverType)
	if errors.Is(err, config.ErrNoDiscoveryEndpoint) {
		config.SetFederation(pelican_url.FederationDiscovery{})
	} else {
		require.NoError(t, err)
	}

	if o.fedMode == federationLazy {
		startFederationMock(t, o)
		config.ResetFederationForTest()
	}
}

// InitClientForTest initializes the Pelican client for a unit test,
// with the same ambient-yaml isolation as InitServerForTest.
//
// Unlike the server path, the client path assumes a fresh start:
// it calls config.ResetConfig up front and re-registers it via t.Cleanup.
// Client tests do not pre-stage Viper state, so the reset is safe.
//
// WithFederationMock / WithLazyFederationMock behave as they do for
// InitServerForTest. WithInitCfg overrides are re-applied after
// config.InitClient, because SetClientDefaults may overwrite some of them.
func InitClientForTest(t testing.TB, opts ...Option) {
	t.Helper()
	o := resolveOptions(opts)

	// Client tests don't pre-stage Viper state, so a reset here is safe
	// (the server path deliberately omits it).
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	cfgDir := prepareConfigDir(t, o)

	InitServerTLSForTest(t, cfgDir)
	require.NoError(t, config.GenerateCert())

	applyInitCfg(t, "InitClientForTest", o.initCfg)

	if o.fedMode == federationEager {
		startFederationMock(t, o)
	}

	require.NoError(t, config.InitClient())

	// SetClientDefaults (inside InitClient) may overwrite caller-supplied
	// params; re-apply so the caller wins.
	applyInitCfg(t, "InitClientForTest", o.initCfg)

	if o.fedMode == federationLazy {
		startFederationMock(t, o)
		config.ResetFederationForTest()
	}
}

// Option customizes InitClientForTest / InitServerForTest.
type Option func(*initOptions)

// WithInitCfg supplies typed param overrides applied between TLS setup
// and config.Init{Server,Client}.
//
// The map may be nil. Calling WithInitCfg multiple times merges the maps;
// later keys win.
func WithInitCfg(m map[param.Param]any) Option {
	return func(o *initOptions) {
		if o.initCfg == nil {
			o.initCfg = map[param.Param]any{}
		}
		for k, v := range m {
			o.initCfg[k] = v
		}
	}
}

// WithServerHostname sets Server.Hostname to the supplied value before
// any TLS cert generation. The default ("localhost") is appropriate for
// almost every test; override only when a test specifically exercises
// hostname-dependent behaviour.
func WithServerHostname(name string) Option {
	return func(o *initOptions) { o.hostname = name }
}

// WithFederationMock starts a CA-signed mock discovery server and points
// Federation.DiscoveryUrl at it BEFORE config.Init{Server,Client}.
// config.InitServer's eager GetFederation call performs a real HTTPS
// discovery roundtrip against the mock — the same code path production
// uses.
//
// fInfo overrides individual fields of the default discovery response
// (nil = built-in fakes for director/registry/broker). kSet overrides
// the published issuer key set (nil = derive from IssuerKeysDirectory).
func WithFederationMock(fInfo *pelican_url.FederationDiscovery, kSet *jwk.Set) Option {
	return func(o *initOptions) {
		o.fedMode = federationEager
		o.fInfo = fInfo
		o.kSet = kSet
	}
}

// WithLazyFederationMock starts a CA-signed mock discovery server AFTER
// config.Init{Server,Client} and resets the federation cache.
//
// Prefer WithFederationMock unless a test specifically needs to suppress
// the eager discovery roundtrip (for example, tests that mutate federation
// parameters between InitServer and first use).
func WithLazyFederationMock(fInfo *pelican_url.FederationDiscovery, kSet *jwk.Set) Option {
	return func(o *initOptions) {
		o.fedMode = federationLazy
		o.fInfo = fInfo
		o.kSet = kSet
	}
}

// ClearFederationURLsForTest sets all five Federation.*Url parameters
// to "" at Viper's override priority, suppressing values from any
// lower-priority config source (notably, the embedded OSDF defaults).
//
// InitServerForTest and InitClientForTest call this automatically,
// before any caller-supplied option runs, so caller-set federation URLs
// survive.
//
// Call it directly only when composing test setup by hand without those
// helpers.
func ClearFederationURLsForTest(t testing.TB) {
	t.Helper()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(""))
	// Federation_Director/Registry/Jwk/BrokerUrl are opaque params
	// with no typed setter; they must be set via param.Set.
	require.NoError(t, param.Set(param.Federation_DirectorUrl, ""))
	require.NoError(t, param.Set(param.Federation_RegistryUrl, ""))
	require.NoError(t, param.Set(param.Federation_JwkUrl, ""))
	require.NoError(t, param.Set(param.Federation_BrokerUrl, ""))
}

// The remainder of this section is the shared, unexported orchestration
// that backs InitServerForTest and InitClientForTest.

// federationMode controls whether and when InitServerForTest /
// InitClientForTest stand up a mock federation discovery endpoint.
type federationMode int

const (
	federationNone  federationMode = iota // no mock discovery endpoint
	federationEager                       // mock set before config.Init*
	federationLazy                        // mock set after config.Init*
)

// initOptions accumulates the variadic configuration
// passed to InitServerForTest and InitClientForTest.
type initOptions struct {
	initCfg  map[param.Param]any
	hostname string
	fedMode  federationMode
	fInfo    *pelican_url.FederationDiscovery
	kSet     *jwk.Set
}

// resolveOptions folds variadic options through their constructors
// and applies the default hostname.
func resolveOptions(opts []Option) initOptions {
	o := initOptions{hostname: "localhost"}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// prepareConfigDir establishes an isolated ConfigDir for the test:
// it allocates a temp dir when ConfigDir is unset,
// writes an empty pelican.yaml to shadow /etc/pelican/pelican.yaml,
// clears OSDF federation URLs, and pins Server.Hostname when unset.
//
// It returns the resolved ConfigDir.
//
// It deliberately does not call config.ResetConfig;
// see InitServerForTest for the rationale.
func prepareConfigDir(t testing.TB, o initOptions) string {
	t.Helper()

	// param.ConfigDir.GetString() always returns "" —
	// ConfigDir is a special internal key absent from parameters.yaml.
	cfgDir := viper.GetString("ConfigDir")
	if cfgDir == "" {
		cfgDir = t.TempDir()
		require.NoError(t, param.ConfigDir.Set(cfgDir))
	}
	require.NoError(t, os.MkdirAll(cfgDir, 0700))

	// Shadow /etc/pelican/pelican.yaml with an empty file,
	// but only when one isn't already present:
	// a caller that set ConfigDir might have staged a real
	// pelican.yaml that we must not clobber.
	cfgFile := filepath.Join(cfgDir, "pelican.yaml")
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		require.NoError(t, os.WriteFile(cfgFile, []byte{}, 0600))
	} else {
		require.NoError(t, err)
	}

	// Clear embedded OSDF federation URLs, which are merged
	// at config-file priority ahead of our empty pelican.yaml.
	ClearFederationURLsForTest(t)

	if !param.Server_Hostname.IsSet() {
		require.NoError(t, param.Server_Hostname.Set(o.hostname))
	}

	return cfgDir
}

// startFederationMock returns the URL of a freshly-started CA-signed
// mock federation discovery server, and sets Federation_DiscoveryUrl
// to that URL.
//
// The cert is signed by the CA at Server_TLSCACertificateFile.
//
// The caller is responsible for resetting any cached federation state
// (e.g., config.ResetFederationForTest).
func startFederationMock(t testing.TB, o initOptions) string {
	t.Helper()

	var pKeySet jwk.Set
	if o.kSet == nil {
		keysDir := param.IssuerKeysDirectory.GetString()
		if keysDir == "" {
			keysDir = filepath.Join(t.TempDir(), "testKeyDir")
			require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))
		}
		var err error
		pKeySet, err = config.GetIssuerPublicJWKS()
		require.NoError(t, err, "Failed to load public JWKS while creating mock federation root")
	} else {
		pKeySet = *o.kSet
	}
	kSetBytes, err := json.Marshal(pKeySet)
	require.NoError(t, err, "Failed to marshal public JWKS while creating mock federation root")

	var getInternalFInfo func() pelican_url.FederationDiscovery
	// This handler runs on the test server's goroutines, so it reports
	// failures with t.Errorf rather than require, which is only safe to
	// call from the test's own goroutine.
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "I only understand GET requests, but you sent me "+r.Method, http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/.well-known/pelican-configuration":
			body, err := json.Marshal(getInternalFInfo())
			if err != nil {
				t.Errorf("Failed to marshal discovery metadata: %v", err)
				http.Error(w, "failed to marshal discovery metadata", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(body); err != nil {
				t.Errorf("Failed to write discovery metadata response: %v", err)
			}
		case "/.well-known/issuer.jwks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(kSetBytes); err != nil {
				t.Errorf("Failed to write issuer JWKS response: %v", err)
			}
		default:
			http.Error(w, "I don't understand this path: "+r.URL.Path, http.StatusNotFound)
		}
	}

	server := configtest.NewTLSServerForTest(t, http.HandlerFunc(handler))
	serverUrl := server.URL
	getInternalFInfo = func() pelican_url.FederationDiscovery {
		info := pelican_url.FederationDiscovery{
			DiscoveryEndpoint: serverUrl,
			DirectorEndpoint:  "https://fake-director.invalid",
			RegistryEndpoint:  "https://fake-registry.invalid",
			BrokerEndpoint:    "https://fake-broker.invalid",
			JwksUri:           fmt.Sprintf("%s/.well-known/issuer.jwks", serverUrl),
		}
		if o.fInfo != nil {
			if o.fInfo.DirectorEndpoint != "" {
				info.DirectorEndpoint = o.fInfo.DirectorEndpoint
			}
			if o.fInfo.RegistryEndpoint != "" {
				info.RegistryEndpoint = o.fInfo.RegistryEndpoint
			}
			if o.fInfo.BrokerEndpoint != "" {
				info.BrokerEndpoint = o.fInfo.BrokerEndpoint
			}
			if o.fInfo.JwksUri != "" {
				info.JwksUri = o.fInfo.JwksUri
			}
			if o.fInfo.DirectorAdvertiseEndpoints != nil {
				info.DirectorAdvertiseEndpoints = o.fInfo.DirectorAdvertiseEndpoints
			}
		}
		return info
	}

	require.NoError(t, param.Federation_DiscoveryUrl.Set(serverUrl))
	return serverUrl
}

// applyInitCfg sets the parameters from initCfg using each param's typed
// setter where possible (StringParam, BoolParam, etc.), falling back to
// param.Set for opaque or unknown types. Panics from type mismatches are
// caught and reported as test failures.
func applyInitCfg(t testing.TB, caller string, initCfg map[param.Param]any) {
	t.Helper()
	for p, val := range initCfg {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic setting param %q to %v (%T): %v", caller, p.GetName(), val, val, r)
				}
			}()
			var err error
			switch tp := p.(type) {
			case param.StringParam:
				err = tp.Set(val.(string))
			case param.BoolParam:
				err = tp.Set(val.(bool))
			case param.IntParam:
				err = tp.Set(val.(int))
			case param.StringSliceParam:
				err = tp.Set(val.([]string))
			case param.DurationParam:
				switch v := val.(type) {
				case string:
					err = tp.SetString(v)
				case time.Duration:
					err = tp.SetString(v.String())
				default:
					t.Fatalf("%s: unsupported value type %T for DurationParam %q", caller, val, p.GetName())
				}
			default:
				err = param.Set(p, val)
			}
			require.NoError(t, err, "%s: failed to set param %q", caller, p.GetName())
		}()
	}
}

// === Test context ===

// TestContext derives a cancelable context and errgroup for a test,
// storing the errgroup in the context under config.EgrpKey so production
// code can retrieve it. The context inherits the test's deadline when
// one is set.
func TestContext(ictx context.Context, t testing.TB) (ctx context.Context, cancel context.CancelFunc, egrp *errgroup.Group) {
	type deadliner interface {
		Deadline() (time.Time, bool)
	}
	if d, ok := t.(deadliner); ok {
		if deadline, ok := d.Deadline(); ok {
			ctx, cancel = context.WithDeadline(ictx, deadline)
		} else {
			ctx, cancel = context.WithCancel(ictx)
		}
	} else {
		ctx, cancel = context.WithCancel(ictx)
	}
	egrp, ctx = errgroup.WithContext(ctx)
	ctx = context.WithValue(ctx, config.EgrpKey, egrp)
	return
}

// === TLS test servers ===

// NewTLSServerForTest starts an HTTPS server with an ephemeral localhost
// leaf certificate signed by an already-provisioned test CA.
//
// The CA must already exist on disk: Server.TLSCACertificateFile and
// Server.TLSCAKey must be set, and both files must be present at those
// paths. InitClientForTest and InitServerForTest establish that state;
// call this only afterward.
func NewTLSServerForTest(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	return configtest.NewTLSServerForTest(t, handler)
}

// InitServerTLSForTest redirects all TLS key and certificate parameters
// to paths inside dir, isolating tests from host configuration.
// Call before any function that generates or reads TLS credentials.
func InitServerTLSForTest(t testing.TB, dir string) {
	t.Helper()
	configtest.InitServerTLSForTest(t, dir)
}

// === Federation, issuer, and registry mocks ===

// MockFederationRoot is a thin shim over startFederationMock + reset of
// the federation cache, retained for callers that compose setup steps by
// hand. New tests should prefer WithFederationMock /
// WithLazyFederationMock on InitClientForTest / InitServerForTest.
//
// The CA at Server_TLSCACertificateFile must already exist on disk;
// the caller is responsible for generating it.
func MockFederationRoot(t testing.TB, fInfo *pelican_url.FederationDiscovery, kSet *jwk.Set) {
	t.Helper()
	startFederationMock(t, initOptions{fInfo: fInfo, kSet: kSet})
	config.ResetFederationForTest()
}

// MockIssuer starts an HTTP test server that answers OIDC discovery
// requests and returns the server URL for use as an issuer URL in tests.
//
// kSet overrides the issuer key set;
// nil generates a fresh key set rooted at IssuerKeysDirectory.
func MockIssuer(t *testing.T, kSet *jwk.Set) string {
	var pKeySetInternal jwk.Set
	var err error
	if kSet == nil {
		keysDir := filepath.Join(t.TempDir(), "testKeyDir")
		require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))
		pKeySetInternal, err = config.GetIssuerPublicJWKS()
		require.NoError(t, err, "Failed to load public JWKS while creating mock issuer")
	} else {
		pKeySetInternal = *kSet
	}
	kSetBytes, err := json.Marshal(pKeySetInternal)
	require.NoError(t, err, "Failed to marshal public JWKS while creating mock issuer")

	var getMyUrl func() string
	// This handler runs on the test server's goroutines, so it reports
	// failures with t.Errorf rather than require, which is only safe to
	// call from the test's own goroutine.
	responseHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "I only understand GET requests, but you sent me "+r.Method, http.StatusMethodNotAllowed)
			return
		}

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			OIDCConfig := fmt.Sprintf(`{"jwks_uri":"%s/.well-known/issuer.jwks"}`, getMyUrl())
			if _, err := w.Write([]byte(OIDCConfig)); err != nil {
				t.Errorf("Failed to write OIDC configuration response: %v", err)
			}
		case "/.well-known/issuer.jwks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(kSetBytes); err != nil {
				t.Errorf("Failed to write issuer JWKS response: %v", err)
			}
		default:
			http.Error(w, "I don't understand this path: "+r.URL.Path, http.StatusNotFound)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(responseHandler))
	serverUrl := server.URL
	getMyUrl = func() string {
		return serverUrl
	}

	t.Cleanup(server.Close)

	return serverUrl
}

// RegistryMockup returns an HTTP test server that responds to registry
// lookups for prefix with a fixed jwks_uri. Each server is bound to one
// prefix; create a new one to switch prefixes.
func RegistryMockup(t *testing.T, prefix string) *httptest.Server {
	// The jwks_uri is a fixed, non-functional value: the mock returns it
	// verbatim and tests only assert on the string, never fetch it, so the
	// host is an obviously-invalid placeholder (RFC 6761 reserves .test).
	jwksUri, err := url.JoinPath("https://registry.test:1234", "/api/v1.0/registry", prefix, ".well-known/issuer.jwks")
	if err != nil {
		t.Fatalf("Failed to build registry JWKS URL for prefix %s: %v", prefix, err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse := `{"jwks_uri": "` + jwksUri + `"}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err = w.Write([]byte(jsonResponse)); err != nil {
			t.Errorf("Failed to write JWKS URI response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// === JWK / JWKS generation ===

// GenerateJWK generates an RSA JWK private key, its corresponding public
// JWKS, and the JSON-encoded public JWKS string.
func GenerateJWK() (jwk.Key, jwk.Set, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}

	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, "", err
	}
	_ = jwkKey.Set(jwk.KeyIDKey, "mykey")
	_ = jwkKey.Set(jwk.AlgorithmKey, "RS256")
	_ = jwkKey.Set(jwk.KeyUsageKey, "sig")

	publicKey, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return nil, nil, "", err
	}

	jwks := jwk.NewSet()
	if err := jwks.AddKey(publicKey); err != nil {
		return nil, nil, "", err
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, nil, "", err
	}

	return jwkKey, jwks, string(jwksBytes), nil
}

// GenerateJWKS generates a fresh ECDSA (ES256) key and returns its public
// JWKS as JSON. Unlike GenerateJWK, it exposes only the serialized public
// set, not the underlying keys.
func GenerateJWKS() (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "Error generating private key")
	}

	pKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to convert ecdsa.PrivateKey to jwk.Key")
	}

	err = jwk.AssignKeyID(pKey)
	if err != nil {
		return "", errors.Wrap(err, "Error assigning kid to private key")
	}

	err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
	if err != nil {
		return "", errors.Wrap(err, "Unable to set algorithm for pKey")
	}

	publicKey, err := pKey.PublicKey()
	if err != nil {
		return "", errors.Wrap(err, "Unable to get the public key from private key")
	}

	jwks := jwk.NewSet()
	err = jwks.AddKey(publicKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to add public key to the jwks")
	}

	jsonData, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return "", errors.Wrap(err, "Unable to marshal the json into string")
	}
	jsonData = append(jsonData, '\n')

	return string(jsonData), nil
}

// === Test logging ===

// SetupTestLogging redirects logrus output into t's log buffer for the
// duration of the test. Use as:
//
//	t.Cleanup(test_utils.SetupTestLogging(t))
func SetupTestLogging(t testing.TB) func() {
	previousGlobalHookState := globalHookEnabled.Swap(false)
	originalOut := logrus.StandardLogger().Out
	originalHooks := logrus.StandardLogger().Hooks
	originalFormatter := logrus.StandardLogger().Formatter
	originalReportCaller := logrus.StandardLogger().ReportCaller

	// Flush any buffered pre-test logs into the hook (visible on failure).
	var bufferedLogs string
	globalLogMu.Lock()
	if globalLogBuffer.Len() > 0 {
		bufferedLogs = globalLogBuffer.String()
		globalLogBuffer.Reset()
	}
	globalLogMu.Unlock()

	// Reset hooks that config initialization might have added.
	config.ResetGlobalLoggingHooks()

	// Disable standard output and use only the test hook.
	logrus.SetOutput(io.Discard)
	logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	logrus.SetReportCaller(true)
	hook := NewTestLogHook(t)
	logrus.AddHook(hook)

	if strings.TrimSpace(bufferedLogs) != "" {
		hook.t.Helper()
		for _, line := range strings.Split(strings.TrimSuffix(bufferedLogs, "\n"), "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				hook.t.Log(trimmed)
			}
		}
	}

	return func() {
		logging.ResetGlobalManager()
		// Reset hooks so they don't fire during subsequent config initialization.
		config.ResetGlobalLoggingHooks()
		logrus.SetOutput(originalOut)
		logrus.StandardLogger().ReplaceHooks(originalHooks)
		logrus.SetFormatter(originalFormatter)
		logrus.SetReportCaller(originalReportCaller)
		globalHookEnabled.Store(previousGlobalHookState)
	}
}

// SetupGlobalTestLogging redirects logrus output away from stdout and
// stderr for the duration of a test binary run. Intended for use in
// TestMain; the returned function restores the original configuration.
func SetupGlobalTestLogging() func() {
	originalOut := logrus.StandardLogger().Out
	originalHooks := logrus.StandardLogger().Hooks
	originalFormatter := logrus.StandardLogger().Formatter
	originalReportCaller := logrus.StandardLogger().ReportCaller
	globalHookEnabled.Store(true)

	globalLogMu.Lock()
	globalLogBuffer.Reset()
	globalLogMu.Unlock()

	logrus.SetOutput(&globalLogBuffer)
	logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	logrus.SetReportCaller(true)
	logrus.AddHook(&globalBufferHook{buf: &globalLogBuffer, mu: &globalLogMu})

	return func() {
		logrus.SetOutput(originalOut)
		logrus.StandardLogger().ReplaceHooks(originalHooks)
		logrus.SetFormatter(originalFormatter)
		logrus.SetReportCaller(originalReportCaller)
	}
}

// TestLogHook forwards log entries to the test log buffer so that they
// appear under the test's output (visible with -v or on failure) and never
// hit stdout/stderr directly.
type TestLogHook struct {
	t testing.TB
}

// NewTestLogHook creates a TestLogHook that routes log entries into t's
// log buffer.
func NewTestLogHook(t testing.TB) *TestLogHook {
	return &TestLogHook{t: t}
}

// Fire writes the entry to the test's log via t.Log.
func (hook *TestLogHook) Fire(entry *logrus.Entry) error {
	hook.t.Helper()
	hook.t.Log(formatEntry(entry))
	return nil
}

// Levels reports that the hook fires for every log level.
func (hook *TestLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Shared buffer (and its guard) for log entries captured before any
// test's own logger is installed;
// see globalBufferHook and SetupGlobalTestLogging.
var (
	globalLogBuffer   bytes.Buffer
	globalLogMu       sync.Mutex
	globalHookEnabled atomic.Bool
)

// globalBufferHook captures log entries emitted before any test runs
// — e.g., during package-level init — into a shared buffer so that they
// can be replayed under the first test's logger.
type globalBufferHook struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

// Fire appends the entry to the shared buffer while capture is enabled.
func (h *globalBufferHook) Fire(entry *logrus.Entry) error {
	if !globalHookEnabled.Load() {
		return nil
	}
	if msg, err := entry.String(); err == nil {
		h.mu.Lock()
		h.buf.WriteString(msg)
		h.mu.Unlock()
	}
	return nil
}

// Levels reports that the hook fires for every log level.
func (h *globalBufferHook) Levels() []logrus.Level { return logrus.AllLevels }

// formatEntry turns a logrus entry into a concise string that includes
// caller information. This avoids the testing.T log location (which would
// otherwise point to the hook) and instead surfaces the originating call
// site to make test output readable.
func formatEntry(entry *logrus.Entry) string {
	loc := ""
	if entry.HasCaller() && entry.Caller != nil {
		loc = fmt.Sprintf("%s:%d: ", filepath.Base(entry.Caller.File), entry.Caller.Line)
	}

	var keys []string
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	msg := entry.Message
	if len(keys) > 0 {
		var fields []string
		for _, k := range keys {
			fields = append(fields, fmt.Sprintf("%s=%v", k, entry.Data[k]))
		}
		msg = fmt.Sprintf("%s [%s]", msg, strings.Join(fields, " "))
	}

	return fmt.Sprintf("%s %s%s %s", entry.Time.Format(time.RFC3339Nano), loc, entry.Level, msg)
}

// === Miscellaneous test helpers ===

// makeBigBuffer creates a buffer of at least 1MB.
func makeBigBuffer() []byte {
	byteBuff := []byte("Hello, World!")
	for {
		byteBuff = append(byteBuff, []byte("Hello, World!")...)
		if len(byteBuff) > 1024*1024 {
			break
		}
	}
	return byteBuff
}

// WriteBigBuffer writes a file at least the specified size in MB.
func WriteBigBuffer(t *testing.T, fp io.WriteCloser, sizeMB int) (size int) {
	defer fp.Close()
	byteBuff := makeBigBuffer()
	size = 0
	for {
		n, err := fp.Write(byteBuff)
		require.NoError(t, err)
		size += n
		if size > sizeMB*1024*1024 {
			break
		}
	}
	return
}

// GetUniqueAvailablePorts returns count unique, available localhost
// ports. Warning: there is a brief window between identifying a port and
// the caller binding to it; another process may claim a port in that
// interval.
func GetUniqueAvailablePorts(count int) ([]int, error) {
	ports := make(map[int]struct{}, count)
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	for len(ports) < count {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}

		addr := ln.Addr().(*net.TCPAddr)
		port := addr.Port

		if _, exists := ports[port]; exists {
			ln.Close()
			continue
		}

		ports[port] = struct{}{}
		listeners = append(listeners, ln)
	}

	portList := make([]int, 0, count)
	for port := range ports {
		portList = append(portList, port)
	}

	return portList, nil
}

// GetTmpStoragePrefixDir returns a 0777 temporary directory suitable for
// use as an origin export StoragePrefix. The XRootD daemon process runs as
// a different user, so it requires world-readable, -writable, and
// -executable permissions.
func GetTmpStoragePrefixDir(t *testing.T) string {
	tmpDir := t.TempDir() + "/tmpdir"

	err := os.MkdirAll(tmpDir, 0777)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	err = os.Chmod(tmpDir, 0777)
	if err != nil {
		t.Fatalf("Failed to set directory permissions: %v", err)
	}

	return tmpDir
}

// ChownToDaemon changes ownership of the given paths to the XRootD daemon user.
// When not running as root this is a no-op (the daemon user is the current user).
func ChownToDaemon(t *testing.T, paths ...string) {
	t.Helper()
	uinfo, err := config.GetDaemonUserInfo()
	require.NoError(t, err)
	for _, p := range paths {
		require.NoError(t, os.Chown(p, uinfo.Uid, uinfo.Gid))
	}
}
