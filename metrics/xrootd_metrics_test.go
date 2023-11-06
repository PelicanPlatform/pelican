package metrics

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func getAuthInfoString(user UserRecord) string {
	return fmt.Sprintf("&p=%s&n=%s&h=[::ffff:172.17.0.2]&o=%s&r=%s&g=&m=&I=4", user.AuthenticationProtocol, user.DN, user.Org, user.Role)
}

func getUserIdString(userId XrdUserId) string {
	return fmt.Sprintf("%s/%s.%s:%s@%s", userId.Prot, userId.User, userId.Pid, userId.Sid, userId.Host)
}

func serializeXrdXrootdMonMap(monMap XrdXrootdMonMap) ([]byte, error) {
	var buf bytes.Buffer

	// Writing the Header
	err := binary.Write(&buf, binary.BigEndian, monMap.Hdr.Code)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Code:", err))
	}
	err = binary.Write(&buf, binary.BigEndian, monMap.Hdr.Pseq)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Pseq:", err))
	}
	err = binary.Write(&buf, binary.BigEndian, monMap.Hdr.Plen)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Plen:", err))
	}
	err = binary.Write(&buf, binary.BigEndian, monMap.Hdr.Stod)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Stod:", err))
	}

	// Writing the Dictid
	err = binary.Write(&buf, binary.BigEndian, monMap.Dictid)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Dictid:", err))
	}

	// Writing the Info slice directly
	err = binary.Write(&buf, binary.BigEndian, monMap.Info)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Info:", err))
	}

	return buf.Bytes(), nil
}

func TestHandlePacket(t *testing.T) {
	t.Run("an-empty-detail-packet-should-return-error", func(t *testing.T) {
		err := HandlePacket([]byte{})
		assert.Error(t, err, "No error reported with an empty detail packet")
	})

	t.Run("record-correct-threads-from-summary-packet", func(t *testing.T) {
		mockShedSummary := SummaryStatistics{
			Version: "0.0",
			Program: "xrootd",
			Stats: []SummaryStat{
				{
					Id:          "sched",
					Threads:     10,
					ThreadsIdle: 8,
				},
			},
		}
		mockShedSummaryBytes, err := xml.Marshal(mockShedSummary)
		assert.NoError(t, err, "Error Marshal Summary packet")

		mockPromThreads := `
		# HELP xrootd_sched_thread_count Number of scheduler threads
		# TYPE xrootd_sched_thread_count gauge
		xrootd_sched_thread_count{state="idle"} 8
		xrootd_sched_thread_count{state="running"} 2
		`
		expectedReader := strings.NewReader(mockPromThreads)

		err = HandlePacket(mockShedSummaryBytes)
		assert.NoError(t, err, "Error handling the packet")
		if err := testutil.CollectAndCompare(Threads, expectedReader, "xrootd_sched_thread_count"); err != nil {
			assert.NoError(t, err, "Collected metric is different from expected")
		}
	})

	t.Run("record-correct-link-from-summary-packet", func(t *testing.T) {
		mockLinkSummaryBase := SummaryStatistics{
			Version: "0.0",
			Program: "xrootd",
			Stats: []SummaryStat{
				{
					Id:              "link",
					LinkConnections: 9,
					LinkInBytes:     99,
					LinkOutBytes:    999,
				},
			},
		}
		mockLinkSummaryInc := SummaryStatistics{
			Version: "0.0",
			Program: "xrootd",
			Stats: []SummaryStat{
				{
					Id:              "link",
					LinkConnections: 10,
					LinkInBytes:     100,
					LinkOutBytes:    1000,
				},
			},
		}
		mockLinkSummaryCMSD := SummaryStatistics{
			Version: "0.0",
			Program: "cmsd",
			Stats: []SummaryStat{
				{
					Id:              "link",
					LinkConnections: 2,
					LinkInBytes:     0,
					LinkOutBytes:    0,
				},
			},
		}
		mockLinkSummaryBaseBytes, err := xml.Marshal(mockLinkSummaryBase)
		assert.NoError(t, err, "Error Marshal Summary packet")
		mockLinkSummaryIncBaseBytes, err := xml.Marshal(mockLinkSummaryInc)
		assert.NoError(t, err, "Error Marshal Summary packet")
		mockLinkSummaryCMSDBaseBytes, err := xml.Marshal(mockLinkSummaryCMSD)
		assert.NoError(t, err, "Error Marshal Summary packet")

		mockPromLinkConnectBase := `
		# HELP xrootd_server_connection_count Aggregate number of server connections
		# TYPE xrootd_server_connection_count counter
		xrootd_server_connection_count 9
		`

		mockPromLinkByteXferBase := `
		# HELP xrootd_server_bytes Number of bytes read into the server
		# TYPE xrootd_server_bytes counter
		xrootd_server_bytes{direction="rx"} 99
		xrootd_server_bytes{direction="tx"} 999
		`

		mockPromLinkConnectInc := `
		# HELP xrootd_server_connection_count Aggregate number of server connections
		# TYPE xrootd_server_connection_count counter
		xrootd_server_connection_count 10
		`

		mockPromLinkByteXferInc := `
		# HELP xrootd_server_bytes Number of bytes read into the server
		# TYPE xrootd_server_bytes counter
		xrootd_server_bytes{direction="rx"} 100
		xrootd_server_bytes{direction="tx"} 1000
		`

		expectedLinkConnectBase := strings.NewReader(mockPromLinkConnectBase)
		expectedLinkByteXferBase := strings.NewReader(mockPromLinkByteXferBase)
		expectedLinkConnectInc := strings.NewReader(mockPromLinkConnectInc)
		expectedLinkByteXferInc := strings.NewReader(mockPromLinkByteXferInc)
		expectedLinkConnectIncDup := strings.NewReader(mockPromLinkConnectInc)
		expectedLinkByteXferIncDup := strings.NewReader(mockPromLinkByteXferInc)

		// First time received a summmary packet
		err = HandlePacket(mockLinkSummaryBaseBytes)
		assert.NoError(t, err, "Error handling the packet")
		if err := testutil.CollectAndCompare(Connections, expectedLinkConnectBase, "xrootd_server_connection_count"); err != nil {
			assert.NoError(t, err, "Collected metric is different from expected")
		}
		if err := testutil.CollectAndCompare(BytesXfer, expectedLinkByteXferBase, "xrootd_server_bytes"); err != nil {
			assert.NoError(t, err, "Collected metric is different from expected")
		}

		// Second time received a summmary packet, with numbers more than first time
		// And metrics should be updated to the max number

		// Have one CMSD summary packets which should be ignored
		err = HandlePacket(mockLinkSummaryCMSDBaseBytes)
		assert.NoError(t, err, "Error handling the packet")
		// Have one CMSD summary packets which should be ignored
		err = HandlePacket(mockLinkSummaryCMSDBaseBytes)
		assert.NoError(t, err, "Error handling the packet")

		err = HandlePacket(mockLinkSummaryIncBaseBytes)
		assert.NoError(t, err, "Error handling the packet")

		if err := testutil.CollectAndCompare(Connections, expectedLinkConnectInc, "xrootd_server_connection_count"); err != nil {
			assert.NoError(t, err, "Collected metric is different from expected")
		}
		if err := testutil.CollectAndCompare(BytesXfer, expectedLinkByteXferInc, "xrootd_server_bytes"); err != nil {
			assert.NoError(t, err, "Collected metric is different from expected")
		}

		// Summary data sent to CMSD shouldn't be recorded into the metrics
		err = HandlePacket(mockLinkSummaryCMSDBaseBytes)
		assert.NoError(t, err, "Error handling the packet")

		if err := testutil.CollectAndCompare(Connections, expectedLinkConnectIncDup, "xrootd_server_connection_count"); err != nil {
			assert.NoError(t, err, "Collected metric is different from expected")
		}
		if err := testutil.CollectAndCompare(BytesXfer, expectedLinkByteXferIncDup, "xrootd_server_bytes"); err != nil {
			assert.NoError(t, err, "Collected metric is different from expected")
		}
	})

	t.Run("auth-packet-should-register-correct-info", func(t *testing.T) {
		mockUserRecord := UserRecord{
			AuthenticationProtocol: "https",
			DN:                     "clientName",
			Role:                   "clientRole",
			Org:                    "clientOrg",
		}
		mockXrdUserId := XrdUserId{
			Prot: "https",
			User: "unknown",
			Pid:  "0",
			Sid:  "143152967831384",
			Host: "fae8c2865de4",
		}
		mockInfo := []byte(getUserIdString(mockXrdUserId) + "\n" + getAuthInfoString(mockUserRecord))
		mockMonMap := XrdXrootdMonMap{
			Hdr: XrdXrootdMonHeader{ // 8B
				Code: 'g',
				Pseq: 1,
				Plen: uint16(12 + len(mockInfo)),
				Stod: int32(time.Now().Unix()),
			},
			Dictid: uint32(0), // 4B
			Info:   mockInfo,
		}

		sessions.DeleteAll()

		buf, err := serializeXrdXrootdMonMap(mockMonMap)
		assert.NoError(t, err, "Error serializing monitor packet")
		HandlePacket(buf)

		assert.Equal(t, 1, len(sessions.Keys()), "Session cache didn't update")
		// The ID seems to be wrong. The length of sid is kXR_int64 while the user id in file hdr is kXR_unt32
		// Aren't the user id supposed to be dictid instead of sid?
		assert.Equal(t, "143152967831384", sessions.Keys()[0].Id, "Session cache didn't update")
	})
}
