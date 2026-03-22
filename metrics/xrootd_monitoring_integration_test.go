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

package metrics_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

// XRootD f-stream record type constants (from XrdXrootdMonData.hh).
// These are spec-defined values, not internal implementation details.
const (
	recIsClose byte = 0 // isClose
	recIsOpen  byte = 1 // isOpen
	recIsTime  byte = 2 // isTime
	recIsXfr   byte = 3 // isXfr
	recIsDisc  byte = 4 // isDisc
)

// drainMonitorChan reads all available packets from the internal monitoring
// channel, waiting up to timeout after the last packet for more to arrive.
func drainMonitorChan(t *testing.T, timeout time.Duration) [][]byte {
	t.Helper()
	ch := metrics.GetInternalMonitorChan()
	var packets [][]byte
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case pkt := <-ch:
			packets = append(packets, pkt)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
		case <-timer.C:
			return packets
		}
	}
}

// packetSummary groups raw monitoring packets by their type code and, for
// 'f' packets, extracts the f-stream sub-record types.
type packetSummary struct {
	uCount     int
	iCount     int
	fCount     int
	fRecTypes  []byte // recIsOpen, recIsClose, etc.
	otherCodes []byte
}

func classifyPackets(t *testing.T, packets [][]byte) packetSummary {
	t.Helper()
	var s packetSummary
	for _, pkt := range packets {
		require.GreaterOrEqual(t, len(pkt), 8, "packet too small: %d bytes", len(pkt))
		code := pkt[0]
		switch code {
		case 'u':
			s.uCount++
		case 'i':
			s.iCount++
		case 'f':
			s.fCount++
			recs := extractFStreamRecTypes(t, pkt)
			s.fRecTypes = append(s.fRecTypes, recs...)
		default:
			s.otherCodes = append(s.otherCodes, code)
		}
	}
	return s
}

// extractFStreamRecTypes walks the f-stream sub-records and returns their types.
func extractFStreamRecTypes(t *testing.T, pkt []byte) []byte {
	t.Helper()
	require.GreaterOrEqual(t, len(pkt), 32, "f-stream packet too small")

	firstHeaderSize := binary.BigEndian.Uint16(pkt[10:12])
	offset := uint32(firstHeaderSize + 8)
	plen := binary.BigEndian.Uint16(pkt[2:4])
	bytesRemain := plen - uint16(offset)

	var types []byte
	for bytesRemain > 0 {
		require.GreaterOrEqual(t, len(pkt), int(offset+8), "not enough bytes for file header")
		fileHdr, err := metrics.ParseFileHeader(pkt[offset : offset+8])
		require.NoError(t, err)
		types = append(types, byte(fileHdr.RecType))
		offset += uint32(fileHdr.RecSize)
		bytesRemain -= uint16(fileHdr.RecSize)
	}
	return types
}

func countByte(s []byte, b byte) int {
	n := 0
	for _, v := range s {
		if v == b {
			n++
		}
	}
	return n
}

// extractProjectFromPackets finds 'i' packets in the slice and extracts the
// project name from the appinfo user-agent string.
func extractProjectFromPackets(t *testing.T, packets [][]byte) string {
	t.Helper()
	for _, pkt := range packets {
		if len(pkt) < 12 || pkt[0] != 'i' {
			continue
		}
		plen := binary.BigEndian.Uint16(pkt[2:4])
		infoSize := int(plen) - 12
		require.GreaterOrEqual(t, len(pkt), 12+infoSize)
		_, rest, err := metrics.GetSIDRest(pkt[12 : 12+infoSize])
		require.NoError(t, err)
		project := utils.ExtractProjectFromUserAgent([]string{rest})
		if project != "" {
			return project
		}
	}
	return ""
}

// extractDNFromPackets finds 'u' (user login) packets and extracts the DN
// from the auth info string (the &n= field).
func extractDNFromPackets(t *testing.T, packets [][]byte) string {
	t.Helper()
	for _, pkt := range packets {
		if len(pkt) < 12 || pkt[0] != 'u' {
			continue
		}
		plen := binary.BigEndian.Uint16(pkt[2:4])
		infoSize := int(plen) - 12
		require.GreaterOrEqual(t, len(pkt), 12+infoSize)
		_, rest, err := metrics.GetSIDRest(pkt[12 : 12+infoSize])
		require.NoError(t, err)
		// rest is the auth info string like "&p=https&n=myDN&o=issuer&r=role"
		for _, part := range strings.Split(rest, "&") {
			if strings.HasPrefix(part, "n=") {
				return strings.TrimPrefix(part, "n=")
			}
		}
	}
	return ""
}

// getMonitoringTestToken generates a WLCG bearer token for the test federation.
func getMonitoringTestToken(t *testing.T) string {
	t.Helper()
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), t.TempDir()))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope, createScope, modScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// TestMonitoringPacketsEndToEnd starts a real federation with a POSIXv2 origin,
// performs uploads and downloads using the Pelican client library, and verifies
// that the correct XRootD-compatible monitoring packets appear on the internal
// monitoring channel.
func TestMonitoringPacketsEndToEnd(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	originConfig := `
Origin:
  StorageType: posixv2
  EnableDirectReads: true
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /storage
      Capabilities: ["PublicReads", "DirectReads", "Writes", "Listings"]
Monitoring:
  MetricAuthorization: false
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// Set up a project name via condor job ad so it appears in monitoring packets
	jobAdFile := filepath.Join(t.TempDir(), "test.job.ad")
	require.NoError(t, os.WriteFile(jobAdFile, []byte("ProjectName = \"MonitoringTestProj\"\n"), 0644))
	t.Setenv("_CONDOR_JOB_AD", jobAdFile)
	client.ResetJobAd()

	// Drain any packets produced during federation startup
	drainMonitorChan(t, 2*time.Second)

	// Enable the shoveler flag so that BeginTransferMonitor generates packets.
	// We do this after federation startup to avoid actually launching the shoveler
	// (which requires a real message queue), but the flag must be set so that
	// BeginTransferMonitor does not short-circuit.
	require.NoError(t, param.Set(param.Shoveler_Enable.GetName(), true))

	testToken := getMonitoringTestToken(t)
	export := ft.Exports[0]
	pelicanHost := fmt.Sprintf("%s:%d", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Create a local file for upload
	testContent := "Hello from monitoring integration test"
	localDir := t.TempDir()
	localFile := filepath.Join(localDir, "upload_test.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	// Create a test file directly in storage for the GET tests
	require.NoError(t, os.WriteFile(
		filepath.Join(export.StoragePrefix, "monitoring_read.txt"),
		[]byte(testContent), 0644))

	t.Run("PUT", func(t *testing.T) {
		drainMonitorChan(t, 500*time.Millisecond)

		uploadURL := fmt.Sprintf("pelican://%s%s/put_monitoring.txt",
			pelicanHost, export.FederationPrefix)

		results, err := client.DoPut(ft.Ctx, localFile, uploadURL, false,
			client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Greater(t, results[0].TransferredBytes, int64(0))

		packets := drainMonitorChan(t, 2*time.Second)
		require.NotEmpty(t, packets, "Should have received monitoring packets")

		s := classifyPackets(t, packets)

		assert.Equal(t, 1, s.uCount, "Expected 1 user-login ('u') packet")
		assert.Equal(t, 1, s.iCount, "Expected 1 appinfo ('i') packet")
		assert.GreaterOrEqual(t, s.fCount, 3, "Expected at least 3 f-stream packets (open, close, disc)")

		assert.Equal(t, 1, countByte(s.fRecTypes, recIsOpen), "Expected 1 isOpen record")
		assert.Equal(t, 1, countByte(s.fRecTypes, recIsClose), "Expected 1 isClose record")
		assert.Equal(t, 1, countByte(s.fRecTypes, recIsDisc), "Expected 1 isDisc record")

		project := extractProjectFromPackets(t, packets)
		assert.Equal(t, "MonitoringTestProj", project, "Project name should appear in 'i' packet")

		// Verify the 'u' packet carries the DN from the token
		dn := extractDNFromPackets(t, packets)
		assert.Equal(t, "origin", dn, "DN in 'u' packet should match the token subject")
	})

	t.Run("GET-directread-authenticated", func(t *testing.T) {
		drainMonitorChan(t, 500*time.Millisecond)

		downloadURL := fmt.Sprintf("pelican://%s%s/monitoring_read.txt?directread",
			pelicanHost, export.FederationPrefix)

		downloadDir := t.TempDir()
		results, err := client.DoGet(ft.Ctx, downloadURL, downloadDir, false,
			client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Equal(t, int64(len(testContent)), results[0].TransferredBytes)

		packets := drainMonitorChan(t, 2*time.Second)
		require.NotEmpty(t, packets)

		s := classifyPackets(t, packets)

		assert.Equal(t, 1, s.uCount, "Expected 1 user-login ('u') packet")
		assert.Equal(t, 1, s.iCount, "Expected 1 appinfo ('i') packet")
		assert.GreaterOrEqual(t, s.fCount, 3, "Expected at least 3 f-stream packets")

		assert.Equal(t, 1, countByte(s.fRecTypes, recIsOpen))
		assert.Equal(t, 1, countByte(s.fRecTypes, recIsClose))
		assert.Equal(t, 1, countByte(s.fRecTypes, recIsDisc))

		project := extractProjectFromPackets(t, packets)
		assert.Equal(t, "MonitoringTestProj", project, "Project name should appear in 'i' packet")

		// Note: even though WithToken is used, the Pelican client drops the
		// token for public-read namespaces because the director returns
		// require-token=false. So the DN in the 'u' packet will be empty.
		dn := extractDNFromPackets(t, packets)
		assert.Empty(t, dn, "DN should be empty because the client drops the token for public-read namespaces")
	})

	t.Run("GET-directread-public", func(t *testing.T) {
		drainMonitorChan(t, 500*time.Millisecond)

		downloadURL := fmt.Sprintf("pelican://%s%s/monitoring_read.txt?directread",
			pelicanHost, export.FederationPrefix)

		downloadDir := t.TempDir()
		// No token — public read
		results, err := client.DoGet(ft.Ctx, downloadURL, downloadDir, false)
		require.NoError(t, err)
		require.NotEmpty(t, results)
		assert.Equal(t, int64(len(testContent)), results[0].TransferredBytes)

		packets := drainMonitorChan(t, 2*time.Second)
		require.NotEmpty(t, packets)

		s := classifyPackets(t, packets)

		assert.Equal(t, 1, s.uCount, "Expected 1 'u' packet for anonymous user")
		assert.Equal(t, 1, s.iCount, "Expected 1 'i' packet")
		assert.GreaterOrEqual(t, s.fCount, 3, "Expected at least 3 f-stream packets")

		assert.Equal(t, 1, countByte(s.fRecTypes, recIsOpen))
		assert.Equal(t, 1, countByte(s.fRecTypes, recIsClose))
		assert.Equal(t, 1, countByte(s.fRecTypes, recIsDisc))

		project := extractProjectFromPackets(t, packets)
		assert.Equal(t, "MonitoringTestProj", project, "Project name should appear in 'i' packet")

		// Public access should have an empty DN
		dn := extractDNFromPackets(t, packets)
		assert.Empty(t, dn, "DN in 'u' packet should be empty for public access")
	})
}
