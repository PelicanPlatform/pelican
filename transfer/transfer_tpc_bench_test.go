//go:build !windows

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

package transfer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// BenchmarkTransferTPCCrossOrigin measures END-TO-END throughput of the transfer
// server running third-party copies between TWO independent origins.
//
// Unlike the manager-level microbenchmark in client_agent, this exercises the
// whole stack a real deployment pays per job: the authenticated HTTP submit,
// per-user credential decryption, the source HEAD against origin #2, the
// destination WebDAV COPY against origin #1, xrootd on both ends, and the
// transfer_jobs bookkeeping. It is the honest answer to "how quickly can we run
// 100 transfer jobs" for the two-origin topology.
//
// Topology (mirrors TestTransferTPCCrossOriginE2E):
//   - origin #1 hosts the transfer API and user1's /data/user1 write area;
//   - origin #2 is an independent origin joined to the fed, hosting user2's
//     /origin2/user2 read area with one seeded source file;
//   - every job copies that source to a distinct destination on origin #1.
//
// Server-side job concurrency is Transfer.MaxConcurrentJobs (default 5); the
// benchmark reports the value it ran with. Because each iteration performs 100
// real transfers, run it with a small count, e.g.:
//
//	go test -tags "client,server" -run '^$' -bench BenchmarkTransferTPCCrossOrigin -benchtime 1x -timeout 900s ./transfer/
//
// It needs the xrootd client plugins on the environment (XRD_PLUGINCONFDIR), the
// same as the TPC e2e tests.
func BenchmarkTransferTPCCrossOrigin(b *testing.B) {
	const numJobs = 100

	ft, _, _, dataDir := setupFedForTransferTPC(b)
	require.NoError(b, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	serverURL := param.Server_ExternalWebUrl.GetString()
	host := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	maxConcurrent := param.Transfer_MaxConcurrentJobs.GetInt()

	const user1, user2 = "testuser", "user2"
	user2Password := randomString(16)

	ctx, cancel := context.WithCancel(ft.Ctx)
	defer cancel()
	o2 := launchSecondOrigin(b, ctx, host, user2, user2Password)

	// Seed a single small source file on origin #2 (read concurrently by all jobs).
	srcDir := filepath.Join(o2.storageDir, user2)
	require.NoError(b, os.MkdirAll(srcDir, 0755))
	require.NoError(b, os.WriteFile(filepath.Join(srcDir, "source.txt"),
		[]byte("cross-origin transfer benchmark payload"), 0644))
	test_utils.ChownToDaemon(b, srcDir, filepath.Join(srcDir, "source.txt"))

	// user1's destination area on origin #1.
	destDir := filepath.Join(dataDir, user1)
	require.NoError(b, os.MkdirAll(destDir, 0755))
	test_utils.ChownToDaemon(b, destDir)

	// Storage tokens: user2 reads /origin2/user2 (origin #2's ns issuer); user1
	// writes /data/user1 (origin #1's ns issuer). Scopes are namespace-relative.
	const destNS = "/data"
	origin1Issuer := serverURL + "/api/v1.0/issuer/ns" + destNS
	srcTokenFile := writeTokenFile(b, "src-token", storageTokenForIssuer(b, o2.issuer, user2,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"+user2)))
	dstTokenFile := writeTokenFile(b, "dst-token", storageTokenForIssuer(b, origin1Issuer, user1,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/"+user1),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/"+user1),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"+user1)))

	transferToken := generateTransferScopeToken(b)
	transferTokenFile := writeTokenFile(b, "transfer-token", transferToken)

	cliPath := getPelicanBinary(b)
	cliEnv := append(os.Environ(),
		"PELICAN_FEDERATION_DISCOVERYURL="+param.Federation_DiscoveryUrl.GetString(),
		"PELICAN_TLSSKIPVERIFY=true",
		"PELICAN_SKIP_TERMINAL_CHECK=1",
		"PELICAN_LOGGING_DISABLEPROGRESSBARS=true",
	)
	srcCredID := cliCredentialAdd(b, cliPath, serverURL, transferTokenFile, "src-user2", srcTokenFile, o2.issuer, cliEnv)
	dstCredID := cliCredentialAdd(b, cliPath, serverURL, transferTokenFile, "dst-user1", dstTokenFile, origin1Issuer, cliEnv)

	sourceURL := fmt.Sprintf("pelican://%s:%d%s/%s/source.txt", host, port, o2.fedPrefix, user2)
	hc := &http.Client{Transport: config.GetTransport()}
	submitURL := serverURL + "/api/v1.0/transfer/jobs"

	// submitJob POSTs one copy job and returns its ID.
	submitJob := func(dest string) (string, error) {
		body, _ := json.Marshal(map[string]any{
			"transfers":            []map[string]any{{"operation": "copy", "source": sourceURL, "destination": dest}},
			"source_credential_id": srcCredID,
			"dest_credential_id":   dstCredID,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, submitURL, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+transferToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 300 {
			return "", fmt.Errorf("submit returned %d: %s", resp.StatusCode, string(rb))
		}
		var jr map[string]any
		if err := json.Unmarshal(rb, &jr); err != nil {
			return "", err
		}
		id, _ := jr["job_id"].(string)
		if id == "" {
			return "", fmt.Errorf("response carried no job_id: %s", string(rb))
		}
		return id, nil
	}

	// waitJob polls one job to a terminal state (tighter than pollTransferJob's
	// 1s cadence, since we're timing throughput).
	statusURL := serverURL + "/api/v1.0/transfer/jobs/"
	waitJob := func(id string, timeout time.Duration) string {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, statusURL+id, nil)
			req.Header.Set("Authorization", "Bearer "+transferToken)
			resp, err := hc.Do(req)
			if err == nil {
				rb, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				var jr map[string]any
				_ = json.Unmarshal(rb, &jr)
				switch st, _ := jr["status"].(string); st {
				case "completed":
					return "completed"
				case "error", "failed", "cancelled":
					return st
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		return "timeout"
	}

	// Warm-up: one job to prime credential decryption, the xrootd data paths, and
	// connection pools, so the timed batch reflects steady-state throughput.
	warmID, err := submitJob(fmt.Sprintf("pelican://%s:%d/data/%s/warm.txt", host, port, user1))
	require.NoError(b, err, "warm-up submit")
	require.Equal(b, "completed", waitJob(warmID, 120*time.Second), "warm-up job must complete")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ids := make([]string, numJobs)
		start := time.Now()

		// Submit all jobs, then await them concurrently. The server's
		// Transfer.MaxConcurrentJobs bounds how many actually run at once.
		for j := 0; j < numJobs; j++ {
			dest := fmt.Sprintf("pelican://%s:%d/data/%s/bench-%d-%d.txt", host, port, user1, i, j)
			id, err := submitJob(dest)
			if err != nil {
				b.Fatalf("submit job %d: %v", j, err)
			}
			ids[j] = id
		}

		var wg sync.WaitGroup
		var failed int32
		for _, id := range ids {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				if waitJob(id, 300*time.Second) != "completed" {
					atomic.AddInt32(&failed, 1)
				}
			}(id)
		}
		wg.Wait()
		elapsed := time.Since(start)

		if failed > 0 {
			b.Fatalf("%d/%d jobs did not complete", failed, numJobs)
		}
		b.ReportMetric(float64(numJobs)/elapsed.Seconds(), "jobs/sec")
		b.ReportMetric(float64(elapsed.Milliseconds())/float64(numJobs), "ms/job")
		b.ReportMetric(float64(maxConcurrent), "max-concurrent")
	}
}
