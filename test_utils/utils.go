/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
)

func TestContext(ictx context.Context, t *testing.T) (ctx context.Context, cancel context.CancelFunc, egrp *errgroup.Group) {
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ictx, deadline)
	} else {
		ctx, cancel = context.WithCancel(ictx)
	}
	egrp, ctx = errgroup.WithContext(ctx)
	ctx = context.WithValue(ctx, config.EgrpKey, egrp)
	return
}

// Creates a buffer of at least 1MB
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

// Writes a file at least the specified size in MB
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

// GenerateJWK generates a JWK private key and a corresponding JWKS public key,
// and the string representation of the public key
func GenerateJWK() (jwk.Key, jwk.Set, string, error) {
	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a JWK from the private key
	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, "", err
	}
	_ = jwkKey.Set(jwk.KeyIDKey, "mykey")
	_ = jwkKey.Set(jwk.AlgorithmKey, "RS256")
	_ = jwkKey.Set(jwk.KeyUsageKey, "sig")

	// Extract the public key
	publicKey, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return nil, nil, "", err
	}

	// Create a JWKS from the public key
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

func GenerateJWKS() (string, error) {
	// Create a private key to use for the test
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "Error generating private key")
	}

	// Convert from raw ecdsa to jwk.Key
	pKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to convert ecdsa.PrivateKey to jwk.Key")
	}

	//Assign Key id to the private key
	err = jwk.AssignKeyID(pKey)
	if err != nil {
		return "", errors.Wrap(err, "Error assigning kid to private key")
	}

	//Set an algorithm for the key
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
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')

	return string(jsonData), nil
}

// For these tests, we only need to lookup key locations. Create a dummy registry that only returns
// the jwks_uri location for the given key. Once a server is instantiated, it will only return
// locations for the provided prefix. To change prefixes, create a new registry mockup.
func RegistryMockup(t *testing.T, prefix string) *httptest.Server {
	registryUrl, _ := url.Parse("https://registry.com:8446")
	path, err := url.JoinPath("/api/v1.0/registry", prefix, ".well-known/issuer.jwks")
	if err != nil {
		t.Fatalf("Failed to parse key path for prefix %s", prefix)
	}
	registryUrl.Path = path

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse := `{"jwks_uri": "` + registryUrl.String() + `"}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonResponse))
	}))
	t.Cleanup(server.Close)
	return server
}

// Initialize the client for a unit test
//
// Will set the configuration to a temporary directory (to
// avoid pulling in global configuration) and set some arbitrary
// viper configurations
func InitClient(t *testing.T, initCfg map[string]any) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))
	for key, val := range initCfg {
		require.NoError(t, param.Set(key, val))
	}

	require.NoError(t, config.InitClient())
}

// getUniqueAvailablePorts returns `count` unique, available ports.
// **WARNING**: There is a small race condition between getting the list of available ports and
// actually binding to them in whatever service uses these values. Be warned they may (but are
// hopefully unlikely to) disappear before you can use them!
func GetUniqueAvailablePorts(count int) ([]int, error) {
	ports := make(map[int]struct{}, count) // A set for tracking unique ports
	listeners := make([]net.Listener, 0, count)
	// Ensure all listeners are closed at the end
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	// Gather unique ports
	for len(ports) < count {
		ln, err := net.Listen("tcp", "127.0.0.1:0") // Epehemeral, random, and available port handed over by the OS
		if err != nil {
			return nil, err
		}

		addr := ln.Addr().(*net.TCPAddr)
		port := addr.Port

		// Ensure uniqueness before adding to the list
		if _, exists := ports[port]; exists {
			ln.Close()
			continue
		}

		// Store the unique port and keep its listener open
		ports[port] = struct{}{}
		listeners = append(listeners, ln)
	}

	// Convert map keys to a sorted slice
	portList := make([]int, 0, count)
	for port := range ports {
		portList = append(portList, port)
	}

	return portList, nil
}

// Create a mock federation root that can respond to requests for metadata and federation keys
func MockFederationRoot(t *testing.T, fInfo *pelican_url.FederationDiscovery, kSet *jwk.Set) {
	// Set up the keys to use in our response jwks
	var pKeySetInternal jwk.Set
	var err error
	if kSet == nil {
		keysDir := filepath.Join(t.TempDir(), "testKeyDir")
		require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), keysDir))
		pKeySetInternal, err = config.GetIssuerPublicJWKS()
		require.NoError(t, err, "Failed to load public JWKS while creating mock federation root")
	} else {
		pKeySetInternal = *kSet
	}
	kSetBytes, err := json.Marshal(pKeySetInternal)
	require.NoError(t, err, "Failed to marshal public JWKS while creating mock federation root")

	// Mock the JSON responses. Values get populated at query time using the getInternalFInfo function
	var getInternalFInfo func() pelican_url.FederationDiscovery
	responseHandler := func(w http.ResponseWriter, r *http.Request) {
		// We only understand GET requests
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("I only understand GET requests, but you sent me " + r.Method))
			require.NoError(t, err)
			return
		}

		path := r.URL.Path
		switch path {
		// Provide base fed root metadata
		case "/.well-known/pelican-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			discoveryMetadata := pelican_url.FederationDiscovery{
				DiscoveryEndpoint:          getInternalFInfo().DiscoveryEndpoint,
				DirectorEndpoint:           getInternalFInfo().DirectorEndpoint,
				RegistryEndpoint:           getInternalFInfo().RegistryEndpoint,
				BrokerEndpoint:             getInternalFInfo().BrokerEndpoint,
				JwksUri:                    getInternalFInfo().JwksUri,
				DirectorAdvertiseEndpoints: getInternalFInfo().DirectorAdvertiseEndpoints,
			}

			discoveryJSONBytes, err := json.Marshal(discoveryMetadata)
			require.NoError(t, err, "Failed to marshal discovery metadata")
			_, err = w.Write(discoveryJSONBytes)
			require.NoError(t, err)
		// If someone follows the jwks_uri value, return the keys
		case "/.well-known/issuer.jwks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(kSetBytes))
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("I don't understand this path: " + path))
			require.NoError(t, err)
		}
	}

	server := httptest.NewTLSServer(http.HandlerFunc(responseHandler))
	serverUrl := server.URL
	getInternalFInfo = func() pelican_url.FederationDiscovery {
		// Pre-populate some fed metadata values
		internalFInfo := pelican_url.FederationDiscovery{
			DiscoveryEndpoint: serverUrl,
			DirectorEndpoint:  "https://fake-director.com",
			RegistryEndpoint:  "https://fake-registry.com",
			BrokerEndpoint:    "https://fake-broker.com",
			JwksUri:           fmt.Sprintf("%s/.well-known/issuer.jwks", serverUrl),
		}

		// Override as needed based on the passed in fInfo
		if fInfo != nil {
			if fInfo.DirectorEndpoint != "" {
				internalFInfo.DirectorEndpoint = fInfo.DirectorEndpoint
			}
			if fInfo.RegistryEndpoint != "" {
				internalFInfo.RegistryEndpoint = fInfo.RegistryEndpoint
			}
			if fInfo.BrokerEndpoint != "" {
				internalFInfo.BrokerEndpoint = fInfo.BrokerEndpoint
			}
			if fInfo.JwksUri != "" {
				internalFInfo.JwksUri = fInfo.JwksUri
			}
			if fInfo.DirectorAdvertiseEndpoints != nil {
				internalFInfo.DirectorAdvertiseEndpoints = fInfo.DirectorAdvertiseEndpoints
			}
		}
		return internalFInfo
	}

	// Cleanup, cleanup, everybody do your share!
	t.Cleanup(server.Close)

	// Finally, set this as the federation discovery URL so tests
	// can "discover" the info
	require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), serverUrl))
	// Set to skip TLS verification for the test server
	require.NoError(t, param.Set(param.TLSSkipVerify.GetName(), true))
}

// Create a mock issuer that responds to request for /.well-known/openid-configuration
// and /.well-known/issuer.jwks
func MockIssuer(t *testing.T, kSet *jwk.Set) string {
	// Set up the keys to use in our response jwks
	var pKeySetInternal jwk.Set
	var err error
	if kSet == nil {
		keysDir := filepath.Join(t.TempDir(), "testKeyDir")
		require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), keysDir))
		pKeySetInternal, err = config.GetIssuerPublicJWKS()
		require.NoError(t, err, "Failed to load public JWKS while creating mock federation root")
	} else {
		pKeySetInternal = *kSet
	}
	kSetBytes, err := json.Marshal(pKeySetInternal)
	require.NoError(t, err, "Failed to marshal public JWKS while creating mock federation root")

	var getMyUrl func() string
	responseHandler := func(w http.ResponseWriter, r *http.Request) {
		// We only understand GET requests
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("I only understand GET requests, but you sent me " + r.Method))
			require.NoError(t, err)
			return
		}

		path := r.URL.Path
		switch path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			OIDCConfig := fmt.Sprintf(`{"jwks_uri":"%s/.well-known/issuer.jwks"}`, getMyUrl())
			_, err = w.Write([]byte(OIDCConfig))
			require.NoError(t, err)
		case "/.well-known/issuer.jwks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(kSetBytes)
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("I don't understand this path: " + path))
			require.NoError(t, err)
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

// TestLogHook forwards log entries to the test log buffer so they appear under the
// test's output (visible with -v or on failure) and never hit stdout/stderr directly.
type TestLogHook struct {
	t *testing.T
}

var (
	globalLogBuffer   bytes.Buffer
	globalLogMu       sync.Mutex
	globalHookEnabled atomic.Bool
)

// globalBufferHook captures log entries into a shared buffer before tests are running
// so they can be replayed under the first test's logger instead of hitting stdout/stderr.
type globalBufferHook struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (h *globalBufferHook) Levels() []logrus.Level { return logrus.AllLevels }

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

// NewTestLogHook creates a new TestLogHook that writes to testing.T's log buffer
func NewTestLogHook(t *testing.T) *TestLogHook {
	return &TestLogHook{t: t}
}

// Fire is called on every log entry
func (hook *TestLogHook) Fire(entry *logrus.Entry) error {
	hook.t.Helper()
	hook.t.Log(formatEntry(entry))
	return nil
}

// Levels defines which log levels this hook applies to
func (hook *TestLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// SetupGlobalTestLogging silences logrus output for an entire package's tests (for use in TestMain).
// It preserves existing logger settings and restores them when the returned cleanup is called.
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
	logrus.StandardLogger().Hooks = make(logrus.LevelHooks)
	logrus.SetReportCaller(true)
	logrus.AddHook(&globalBufferHook{buf: &globalLogBuffer, mu: &globalLogMu})

	return func() {
		logrus.SetOutput(originalOut)
		logrus.StandardLogger().Hooks = originalHooks
		logrus.SetFormatter(originalFormatter)
		logrus.SetReportCaller(originalReportCaller)
	}
}

// SetupTestLogging configures logrus to write to the test's log buffer.
// This should be called at the beginning of tests to ensure clean output.
// Returns a cleanup function that should be called with defer.
func SetupTestLogging(t *testing.T) func() {
	previousGlobalHookState := globalHookEnabled.Swap(false)
	// Save the original logger configuration
	originalOut := logrus.StandardLogger().Out
	originalHooks := logrus.StandardLogger().Hooks
	originalFormatter := logrus.StandardLogger().Formatter
	originalReportCaller := logrus.StandardLogger().ReportCaller

	// Flush any buffered global logs into the test hook (only emitted on failure)
	var bufferedLogs string
	globalLogMu.Lock()
	if globalLogBuffer.Len() > 0 {
		bufferedLogs = globalLogBuffer.String()
		globalLogBuffer.Reset()
	}
	globalLogMu.Unlock()

	// Reset global logging hooks that may have been added by config initialization
	config.ResetGlobalLoggingHooks()

	// Disable standard output and use only the test hook
	logrus.SetOutput(io.Discard)
	logrus.StandardLogger().Hooks = make(logrus.LevelHooks)
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

	// Return cleanup function
	return func() {
		logging.ResetGlobalManager()
		// Reset global logging hooks so they don't output during subsequent config initialization
		config.ResetGlobalLoggingHooks()
		logrus.SetOutput(originalOut)
		logrus.StandardLogger().Hooks = originalHooks
		logrus.SetFormatter(originalFormatter)
		logrus.SetReportCaller(originalReportCaller)
		globalHookEnabled.Store(previousGlobalHookState)
	}
}

// formatEntry turns a logrus entry into a concise string that includes caller information.
// This avoids the testing.T log location (which would otherwise point to the hook) and instead
// surfaces the originating call site to make test output readable.
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
