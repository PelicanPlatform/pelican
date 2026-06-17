//go:build server

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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/lotman"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestConstructLotsAPIURL(t *testing.T) {
	t.Run("empty-server-url", func(t *testing.T) {
		_, err := constructLotsAPIURL("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--server flag")
	})
	t.Run("invalid-url-format", func(t *testing.T) {
		_, err := constructLotsAPIURL("://bad")
		require.Error(t, err)
	})
	t.Run("non-https-scheme", func(t *testing.T) {
		_, err := constructLotsAPIURL("http://cache.example.com:8447")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})
	t.Run("valid", func(t *testing.T) {
		u, err := constructLotsAPIURL("https://cache.example.com:8447/")
		require.NoError(t, err)
		assert.Equal(t, "cache.example.com:8447", u.Host)
		assert.Equal(t, serverLotsAPIPath, u.Path)
	})
}

// newMPATestCmd builds a command registering the quota/time flags buildMPAInput reads.
func newMPATestCmd() *cobra.Command {
	c := &cobra.Command{}
	c.Flags().Float64("dedicated-gb", 0, "")
	c.Flags().Float64("opportunistic-gb", 0, "")
	c.Flags().Int64("max-objects", 0, "")
	c.Flags().String("creation", "", "")
	c.Flags().String("expiration", "", "")
	c.Flags().String("deletion", "", "")
	return c
}

func TestBuildMPAInput(t *testing.T) {
	t.Run("only-set-flags-are-populated", func(t *testing.T) {
		cmd := newMPATestCmd()
		require.NoError(t, cmd.Flags().Set("dedicated-gb", "10"))
		require.NoError(t, cmd.Flags().Set("max-objects", "7"))

		mpa, err := buildMPAInput(cmd)
		require.NoError(t, err)
		require.NotNil(t, mpa.DedicatedGB)
		assert.Equal(t, 10.0, *mpa.DedicatedGB)
		require.NotNil(t, mpa.MaxNumObjects)
		assert.Equal(t, int64(7), *mpa.MaxNumObjects)
		// Unset flags stay nil.
		assert.Nil(t, mpa.OpportunisticGB)
		assert.Nil(t, mpa.CreationTimeMs)
		assert.Nil(t, mpa.ExpirationTimeMs)
		assert.Nil(t, mpa.DeletionTimeMs)
	})

	t.Run("nothing-set", func(t *testing.T) {
		mpa, err := buildMPAInput(newMPATestCmd())
		require.NoError(t, err)
		assert.Nil(t, mpa.DedicatedGB)
		assert.Nil(t, mpa.OpportunisticGB)
		assert.Nil(t, mpa.MaxNumObjects)
		assert.Nil(t, mpa.ExpirationTimeMs)
	})

	t.Run("time-parsed-to-millis", func(t *testing.T) {
		const ts = "2026-01-02 03:04:05"
		cmd := newMPATestCmd()
		require.NoError(t, cmd.Flags().Set("expiration", ts))
		mpa, err := buildMPAInput(cmd)
		require.NoError(t, err)
		require.NotNil(t, mpa.ExpirationTimeMs)
		// The flag is parsed as UTC and converted to Unix milliseconds.
		want, perr := time.Parse("2006-01-02 15:04:05", ts)
		require.NoError(t, perr)
		assert.Equal(t, want.UTC().UnixMilli(), *mpa.ExpirationTimeMs)
	})

	t.Run("bad-time-errors", func(t *testing.T) {
		cmd := newMPATestCmd()
		require.NoError(t, cmd.Flags().Set("deletion", "not-a-time"))
		_, err := buildMPAInput(cmd)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deletion")
	})
}

// recordedReq captures the last request the mock server received.
type recordedReq struct {
	mu     sync.Mutex
	method string
	path   string
	body   []byte
}

func (r *recordedReq) set(method, path string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.method, r.path, r.body = method, path, body
}

func (r *recordedReq) get() (string, string, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.method, r.path, r.body
}

// TestLotCommandsAgainstMockServer exercises each verb's request construction
// and response parsing end-to-end against a TLS mock of the lot API.
func TestLotCommandsAgainstMockServer(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	// Generate a CA + host certificate via the config module and trust it
	// through the standard client transport, so the round-trip uses real TLS
	// verification (no InsecureSkipVerify). The generated cert's SANs include
	// the configured Server.Hostname.
	dir := t.TempDir()
	require.NoError(t, param.ConfigDir.Set(dir))
	require.NoError(t, param.Server_Hostname.Set("localhost"))
	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(context.Background(), server_structs.OriginType))
	serverCert, err := tls.LoadX509KeyPair(param.Server_TLSCertificateChain.GetString(), param.Server_TLSKey.GetString())
	require.NoError(t, err)

	last := &recordedReq{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		last.set(r.Method, r.URL.Path, body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == serverLotsAPIPath:
			_, _ = w.Write([]byte(`{"lots":["lot-a","lot-b"]}`))
		case r.Method == http.MethodPost && r.URL.Path == serverLotsAPIPath:
			_, _ = w.Write([]byte(`{"reservationId":"lot-new","status":"active"}`))
		case r.Method == http.MethodGet && r.URL.Path == serverLotsAPIPath+"/lot-a":
			_, _ = w.Write([]byte(`{"reservationId":"lot-a","status":"active","dedicatedGB":10}`))
		case r.Method == http.MethodPatch && r.URL.Path == serverLotsAPIPath+"/lot-a":
			_, _ = w.Write([]byte(`{"reservationId":"lot-a","status":"active"}`))
		case r.Method == http.MethodDelete && r.URL.Path == serverLotsAPIPath+"/lot-a":
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == serverLotsAPIPath+"/lot-a/reclaim":
			_, _ = w.Write([]byte(`{"lotName":"lot-a","status":"reclaimed","reclaimedAtMs":1}`))
		case r.Method == http.MethodGet && r.URL.Path == serverLotsAPIPath+"/lot-a/usage":
			_, _ = w.Write([]byte(`{"dedicatedGB":{"total":5}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"msg":"unexpected request"}`))
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	// server.URL is https://127.0.0.1:PORT; use "localhost" so the request host
	// matches a SAN in the generated certificate.
	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)

	tokenFile := filepath.Join(t.TempDir(), "admin.tok")
	require.NoError(t, os.WriteFile(tokenFile, []byte("admin-bearer-token"), 0600))

	lotServerURLStr = "https://localhost:" + parsed.Port()
	lotTokenLocation = tokenFile
	t.Cleanup(func() {
		lotServerURLStr = ""
		lotTokenLocation = ""
	})

	t.Run("list", func(t *testing.T) {
		require.NoError(t, listLots(lotListCmd, nil))
		m, p, _ := last.get()
		assert.Equal(t, http.MethodGet, m)
		assert.Equal(t, serverLotsAPIPath, p)
	})

	t.Run("get", func(t *testing.T) {
		require.NoError(t, getLot(lotGetCmd, []string{"lot-a"}))
		m, p, _ := last.get()
		assert.Equal(t, http.MethodGet, m)
		assert.Equal(t, serverLotsAPIPath+"/lot-a", p)
	})

	t.Run("create", func(t *testing.T) {
		require.NoError(t, lotCreateCmd.Flags().Set("path", "/atlas"))
		require.NoError(t, lotCreateCmd.Flags().Set("recursive", "true"))
		require.NoError(t, lotCreateCmd.Flags().Set("dedicated-gb", "10"))
		require.NoError(t, createLot(lotCreateCmd, nil))

		m, p, body := last.get()
		assert.Equal(t, http.MethodPost, m)
		assert.Equal(t, serverLotsAPIPath, p)
		var req lotman.CreateLotRequest
		require.NoError(t, json.Unmarshal(body, &req))
		require.Len(t, req.Paths, 1)
		assert.Equal(t, "/atlas", req.Paths[0].Path)
		assert.True(t, req.Paths[0].Recursive)
		require.NotNil(t, req.ManagementPolicyAttrs)
		require.NotNil(t, req.ManagementPolicyAttrs.DedicatedGB)
		assert.Equal(t, 10.0, *req.ManagementPolicyAttrs.DedicatedGB)
	})

	t.Run("update", func(t *testing.T) {
		require.NoError(t, lotUpdateCmd.Flags().Set("opportunistic-gb", "3"))
		require.NoError(t, updateLot(lotUpdateCmd, []string{"lot-a"}))
		m, p, body := last.get()
		assert.Equal(t, http.MethodPatch, m)
		assert.Equal(t, serverLotsAPIPath+"/lot-a", p)
		var req lotman.PatchLotRequest
		require.NoError(t, json.Unmarshal(body, &req))
		require.NotNil(t, req.ManagementPolicyAttrs)
		require.NotNil(t, req.ManagementPolicyAttrs.OpportunisticGB)
		assert.Equal(t, 3.0, *req.ManagementPolicyAttrs.OpportunisticGB)
	})

	t.Run("update-nothing-set-errors", func(t *testing.T) {
		// A fresh command with the MPA flags but none set must be rejected.
		require.Error(t, updateLot(newMPATestCmd(), []string{"lot-a"}))
	})

	t.Run("delete", func(t *testing.T) {
		require.NoError(t, deleteLot(lotDeleteCmd, []string{"lot-a"}))
		m, p, _ := last.get()
		assert.Equal(t, http.MethodDelete, m)
		assert.Equal(t, serverLotsAPIPath+"/lot-a", p)
	})

	t.Run("reclaim", func(t *testing.T) {
		require.NoError(t, lotReclaimCmd.Flags().Set("reason", "cleanup"))
		require.NoError(t, reclaimLot(lotReclaimCmd, []string{"lot-a"}))
		m, p, body := last.get()
		assert.Equal(t, http.MethodPost, m)
		assert.Equal(t, serverLotsAPIPath+"/lot-a/reclaim", p)
		var req lotman.ReclaimLotRequest
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Equal(t, "cleanup", req.Reason)
	})

	t.Run("usage", func(t *testing.T) {
		require.NoError(t, getLotUsage(lotUsageCmd, []string{"lot-a"}))
		m, p, _ := last.get()
		assert.Equal(t, http.MethodGet, m)
		assert.Equal(t, serverLotsAPIPath+"/lot-a/usage", p)
	})
}
