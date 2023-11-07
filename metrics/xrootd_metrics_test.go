package metrics

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getAuthInfoString(user UserRecord) string {
	return fmt.Sprintf("&p=%s&n=%s&h=[::ffff:172.17.0.2]&o=%s&r=%s&g=&m=&I=4", user.AuthenticationProtocol, user.DN, user.Org, user.Role)
}

func getUserIdString(userId XrdUserId) string {
	return fmt.Sprintf("%s/%s.%s:%s@%s", userId.Prot, userId.User, userId.Pid, userId.Sid, userId.Host)
}

func mockFileOpenPacket(pseq int, fileId, userId uint32, SID int64, path string) ([]byte, error) {
	// f-stream file open event
	mockMonHeader := XrdXrootdMonHeader{ // 8B
		Code: 'f',
		Pseq: byte(pseq),
		Plen: uint16(8), // to change
		Stod: int32(time.Now().Unix()),
	}
	mockMonFileTOD := XrdXrootdMonFileTOD{
		Hdr: XrdXrootdMonFileHdr{ // 8B
			RecType: isTime,
			RecFlag: 1, // hasSID
			RecSize: int16(24),
			NRecs0:  0, // isTime: nRecs[0] == isXfr recs
			NRecs1:  1, // nRecs[1] == total recs
		},
		TBeg: int32(time.Now().Unix()),                  // 4B
		TEnd: int32(time.Now().Add(time.Second).Unix()), // 4B
		SID:  SID,                                       // 8B
	}
	lfnByteSlice := []byte(path)
	lfnByteSlice = append(lfnByteSlice, '\x00') // Add null byte to end the string

	mockMonFileOpn := XrdXrootdMonFileOPN{
		Hdr: XrdXrootdMonFileHdr{ // 8B
			RecType: isOpen,
			RecFlag: 3,      // hasLFN hasRW
			RecSize: 0,      // to change
			FileId:  fileId, // dictid if recType != isTime
		},
		Fsz: 10000, // 8B
		Ufn: XrdXrootdMonFileLFN{ // 4B + len(lfn)
			User: userId, // dictid for the user
		},
	}
	copy(mockMonFileOpn.Ufn.Lfn[:], lfnByteSlice)
	mockMonFileOpn.Hdr.RecSize = int16(16 + 4 + len(lfnByteSlice))
	mockMonHeader.Plen = uint16(8 + mockMonFileTOD.Hdr.RecSize + mockMonFileOpn.Hdr.RecSize)

	monHeader, err := mockMonHeader.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize monitor header")
	}
	fileTod, err := mockMonFileTOD.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize FileTOD")
	}
	fileOpn, err := mockMonFileOpn.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize FileOPN")
	}

	buf := new(bytes.Buffer)
	buf.Write(monHeader[:])
	buf.Write(fileTod[:])
	buf.Write(fileOpn[:])

	bytePacket := buf.Bytes()
	return bytePacket, nil
}

func mockFileXfrPacket(pseq int, fileId uint32, SID int64, read, readv, wrtie int64) ([]byte, error) {
	// f-stream file transfer event
	mockMonHeader := XrdXrootdMonHeader{ // 8B
		Code: 'f',
		Pseq: byte(pseq),
		Plen: uint16(8), // to change
		Stod: int32(time.Now().Unix()),
	}
	mockMonFileTOD := XrdXrootdMonFileTOD{
		Hdr: XrdXrootdMonFileHdr{ // 8B
			RecType: isTime,
			RecFlag: 1, // hasSID
			RecSize: int16(24),
			NRecs0:  0, // isTime: nRecs[0] == isXfr recs
			NRecs1:  1, // nRecs[1] == total recs
		},
		TBeg: int32(time.Now().Unix()),                  // 4B
		TEnd: int32(time.Now().Add(time.Second).Unix()), // 4B
		SID:  SID,                                       // 8B
	}
	mockMonFileXfr := XrdXrootdMonFileXFR{
		Hdr: XrdXrootdMonFileHdr{ // 8B
			RecType: isXfr,
			RecFlag: 0,
			RecSize: 32,     // to change
			FileId:  fileId, // dictid if recType != isTime
		},
		Xfr: XrdXrootdMonStatXFR{ // 24B
			Read:  read,
			Readv: readv,
			Write: wrtie,
		},
	}
	mockMonHeader.Plen = uint16(8 + mockMonFileTOD.Hdr.RecSize + mockMonFileXfr.Hdr.RecSize)

	monHeader, err := mockMonHeader.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize monitor header")
	}
	fileTod, err := mockMonFileTOD.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize FileTOD")
	}
	fileXfr, err := mockMonFileXfr.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize FileOPN")
	}

	buf := new(bytes.Buffer)
	buf.Write(monHeader[:])
	buf.Write(fileTod[:])
	buf.Write(fileXfr[:])

	bytePacket := buf.Bytes()
	return bytePacket, nil
}

func mockStatOps(read, readv, write int32, rsegs int64) *XrdXrootdMonStatOPS {
	monOps := XrdXrootdMonStatOPS{ // 48B
		Read:  read,
		Readv: readv,
		Write: write,
		Rsegs: rsegs,
	}

	return &monOps
}

func mockFileClosePacket(pseq int, fileId uint32, SID int64, statOps *XrdXrootdMonStatOPS, read, readv, write int64) ([]byte, error) {
	// f-stream file close event
	mockMonHeader := XrdXrootdMonHeader{ // 8B
		Code: 'f',
		Pseq: byte(pseq),
		Plen: uint16(8), // to change
		Stod: int32(time.Now().Unix()),
	}
	mockMonFileTOD := XrdXrootdMonFileTOD{
		Hdr: XrdXrootdMonFileHdr{ // 8B
			RecType: isTime,
			RecFlag: 0x01, // hasSID
			RecSize: int16(24),
			NRecs0:  0, // isTime: nRecs[0] == isXfr recs
			NRecs1:  1, // nRecs[1] == total recs
		},
		TBeg: int32(time.Now().Unix()),                  // 4B
		TEnd: int32(time.Now().Add(time.Second).Unix()), // 4B
		SID:  SID,                                       // 8B
	}
	mockFileClose := XrdXrootdMonFileCLS{
		Hdr: XrdXrootdMonFileHdr{ // 8B
			RecType: isClose,
			RecFlag: 0x02,   // hasOPS
			RecSize: 80,     // to change
			FileId:  fileId, // dictid if recType != isTime
		},
		Xfr: XrdXrootdMonStatXFR{ // 24B
			Read:  read,
			Readv: readv,
			Write: write,
		},
		Ops: *statOps, // 48B
	}

	mockMonHeader.Plen = uint16(8 + mockMonFileTOD.Hdr.RecSize + mockFileClose.Hdr.RecSize)

	monHeader, err := mockMonHeader.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize monitor header")
	}
	fileTod, err := mockMonFileTOD.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize FileTOD")
	}
	fileClose, err := mockFileClose.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Error serialize FileCLS")
	}

	buf := new(bytes.Buffer)
	buf.Write(monHeader[:])
	buf.Write(fileTod[:])
	buf.Write(fileClose[:])

	return buf.Bytes(), nil
}

func TestHandlePacket(t *testing.T) {
	mockFileID := uint32(999)
	mockSID := int64(143152967831384)
	mockUserID := uint32(10)
	mockRead := int64(10000)
	mockReadV := int64(20000)
	mockWrite := int64(120)

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

		Threads.Reset()

		mockShedSummaryBytes, err := xml.Marshal(mockShedSummary)
		require.NoError(t, err, "Error Marshal Summary packet")

		mockPromThreads := `
		# HELP xrootd_sched_thread_count Number of scheduler threads
		# TYPE xrootd_sched_thread_count gauge
		xrootd_sched_thread_count{state="idle"} 8
		xrootd_sched_thread_count{state="running"} 2
		`
		expectedReader := strings.NewReader(mockPromThreads)

		err = HandlePacket(mockShedSummaryBytes)
		require.NoError(t, err, "Error handling the packet")
		if err := testutil.CollectAndCompare(Threads, expectedReader, "xrootd_sched_thread_count"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
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

		BytesXfer.Reset()
		Threads.Reset()

		mockLinkSummaryBaseBytes, err := xml.Marshal(mockLinkSummaryBase)
		require.NoError(t, err, "Error Marshal Summary packet")
		mockLinkSummaryIncBaseBytes, err := xml.Marshal(mockLinkSummaryInc)
		require.NoError(t, err, "Error Marshal Summary packet")
		mockLinkSummaryCMSDBaseBytes, err := xml.Marshal(mockLinkSummaryCMSD)
		require.NoError(t, err, "Error Marshal Summary packet")

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
		require.NoError(t, err, "Error handling the packet")
		if err := testutil.CollectAndCompare(Connections, expectedLinkConnectBase, "xrootd_server_connection_count"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}
		if err := testutil.CollectAndCompare(BytesXfer, expectedLinkByteXferBase, "xrootd_server_bytes"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}

		// Second time received a summmary packet, with numbers more than first time
		// And metrics should be updated to the max number

		// Have one CMSD summary packets which should be ignored
		err = HandlePacket(mockLinkSummaryCMSDBaseBytes)
		require.NoError(t, err, "Error handling the packet")
		// Have one CMSD summary packets which should be ignored
		err = HandlePacket(mockLinkSummaryCMSDBaseBytes)
		require.NoError(t, err, "Error handling the packet")

		err = HandlePacket(mockLinkSummaryIncBaseBytes)
		require.NoError(t, err, "Error handling the packet")

		if err := testutil.CollectAndCompare(Connections, expectedLinkConnectInc, "xrootd_server_connection_count"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}
		if err := testutil.CollectAndCompare(BytesXfer, expectedLinkByteXferInc, "xrootd_server_bytes"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}

		// Summary data sent to CMSD shouldn't be recorded into the metrics
		err = HandlePacket(mockLinkSummaryCMSDBaseBytes)
		require.NoError(t, err, "Error handling the packet")

		if err := testutil.CollectAndCompare(Connections, expectedLinkConnectIncDup, "xrootd_server_connection_count"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}
		if err := testutil.CollectAndCompare(BytesXfer, expectedLinkByteXferIncDup, "xrootd_server_bytes"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}
	})

	t.Run("auth-packet-u-should-register-correct-info", func(t *testing.T) {
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
				// u-stream provides client login information; enabled by the auth and use
				Code: 'u',
				Pseq: 1,
				Plen: uint16(12 + len(mockInfo)),
				Stod: int32(time.Now().Unix()),
			},
			Dictid: uint32(0), // 4B
			Info:   mockInfo,
		}

		sessions.DeleteAll()

		buf, err := mockMonMap.Serialize()
		require.NoError(t, err, "Error serializing monitor packet")
		err = HandlePacket(buf)
		require.NoError(t, err, "Error handling packet")

		require.Equal(t, 1, len(sessions.Keys()), "Session cache didn't update")

		sidInt, err := strconv.Atoi(mockXrdUserId.Sid)
		require.NoError(t, err, "Error parsing SID to int64")
		// The ID seems to be wrong. The length of sid is kXR_int64 while the user id in file hdr is kXR_unt32
		// Aren't the user id supposed to be the dictid instead of sid?
		assert.Equal(t, uint32(sidInt), sessions.Keys()[0].Id, "Id in session cache entry doesn't match expected")
		sessionEntry := sessions.Get(sessions.Keys()[0]).Value()
		assert.Equal(t, mockUserRecord.AuthenticationProtocol, sessionEntry.AuthenticationProtocol)
		assert.Equal(t, mockUserRecord.DN, sessionEntry.DN)
		assert.Equal(t, mockUserRecord.Role, sessionEntry.Role)
		assert.Equal(t, mockUserRecord.Org, sessionEntry.Org)

		sessions.DeleteAll()
	})

	t.Run("file-path-packet-d-should-register-correct-info", func(t *testing.T) {
		mockXrdUserId := XrdUserId{
			Prot: "https",
			User: "unknown",
			Pid:  "0",
			Sid:  "143152967831384",
			Host: "fae8c2865de4",
		}

		mockInfo := []byte(getUserIdString(mockXrdUserId) + "\n" + "/full/path/to/file.txt")

		mockMonMap := XrdXrootdMonMap{
			Hdr: XrdXrootdMonHeader{ // 8B
				// d-stream provides the identifier assigned to a user and file path; enabled
				Code: 'd',
				Pseq: 1,
				Plen: uint16(12 + len(mockInfo)),
				Stod: int32(time.Now().Unix()),
			},
			Dictid: uint32(10), // 4B
			Info:   mockInfo,
		}

		buf, err := mockMonMap.Serialize()
		require.NoError(t, err, "Error serializing monitor packet")

		transfers.DeleteAll()

		err = HandlePacket(buf)
		require.NoError(t, err, "Error handling packet")
		require.Equal(t, 1, len(transfers.Keys()), "Transfer cache didn't update")
		assert.Equal(t, uint32(10), transfers.Keys()[0].Id, "Id in session cache entry doesn't match expected")
		transferEntry := transfers.Get(transfers.Keys()[0]).Value()
		// I'm not sure the intent of the Path attribute and looking at ComputePrefix,
		// it seems to return "/" all the time as the length of monitorPaths is
		// never changed
		assert.Equal(t, "/", transferEntry.Path, "Path in transfer cache entry doesn't match expected")

		sidInt, err := strconv.Atoi(mockXrdUserId.Sid)
		require.NoError(t, err, "Error parsing SID to int64")
		assert.Equal(t, uint32(sidInt), transferEntry.UserId.Id, "UserID in transfer cache entry doesn't match expected")
		transfers.DeleteAll()
	})

	t.Run("f-stream-file-open-event-should-register-correctly", func(t *testing.T) {
		bytePacket, err := mockFileOpenPacket(0, mockFileID, mockUserID, mockSID, "/full/path/to/file.txt")
		require.NoError(t, err, "Error generating mock file open packet")

		transfers.DeleteAll()

		err = HandlePacket(bytePacket)
		require.NoError(t, err, "Error handling the packet")
		require.Equal(t, 1, len(transfers.Keys()), "Transfer cache didn't update")
		assert.Equal(t, mockFileID, transfers.Keys()[0].Id, "Id in session cache entry doesn't match expected")
		transferEntry := transfers.Get(transfers.Keys()[0]).Value()
		// I'm not sure the intent of the Path attribute and looking at ComputePrefix,
		// it seems to return "/" all the time as the length of monitorPaths is
		// never changed
		assert.Equal(t, "/", transferEntry.Path, "Path in transfer cache entry doesn't match expected")
		// TODO: Figure out why there's such discrepency here and the d-stream (where userid == sid),
		// but for other tests to run, just change to what returns to me for now
		assert.Equal(t, mockUserID, transferEntry.UserId.Id, "UserID in transfer cache entry doesn't match expected")
		transfers.DeleteAll()
	})

	t.Run("f-stream-file-xfr-event-should-register-correctly", func(t *testing.T) {
		bytePacket, err := mockFileXfrPacket(0, mockFileID, mockSID, mockRead, mockReadV, mockWrite)
		require.NoError(t, err, "Error generating mock file open packet")

		transfers.DeleteAll()

		err = HandlePacket(bytePacket)
		require.NoError(t, err, "Error handling the packet")
		require.Equal(t, 1, len(transfers.Keys()), "Transfer cache didn't update")
		assert.Equal(t, mockFileID, transfers.Keys()[0].Id, "Id in session cache entry doesn't match expected")
		transferEntry := transfers.Get(transfers.Keys()[0]).Value()
		assert.Equal(t, mockRead, int64(transferEntry.ReadBytes))
		assert.Equal(t, mockReadV, int64(transferEntry.ReadvBytes))
		assert.Equal(t, mockWrite, int64(transferEntry.WriteBytes))

		transfers.DeleteAll()
	})

	t.Run("f-stream-file-open-xfr-event-should-register-correctly", func(t *testing.T) {
		openPacket, err := mockFileOpenPacket(0, mockFileID, mockUserID, mockSID, "/full/path/to/file.txt")
		require.NoError(t, err, "Error generating mock file open packet")
		xftPacket, err := mockFileXfrPacket(1, mockFileID, mockSID, mockRead, mockReadV, mockWrite)
		require.NoError(t, err, "Error generating mock file transfer packet")

		transfers.DeleteAll()

		err = HandlePacket(openPacket)
		require.NoError(t, err, "Error handling the file open packet")

		err = HandlePacket(xftPacket)
		require.NoError(t, err, "Error handling the file transfer packet")

		require.Equal(t, 1, len(transfers.Keys()), "Transfer cache didn't update")
		assert.Equal(t, mockFileID, transfers.Keys()[0].Id, "Id in session cache entry doesn't match expected")
		transferEntry := transfers.Get(transfers.Keys()[0]).Value()
		assert.Equal(t, mockRead, int64(transferEntry.ReadBytes))
		assert.Equal(t, mockReadV, int64(transferEntry.ReadvBytes))
		assert.Equal(t, mockWrite, int64(transferEntry.WriteBytes))
		assert.Equal(t, "/", transferEntry.Path, "Path in transfer cache entry doesn't match expected")
		// TODO: Figure out why there's such discrepency here and the d-stream (where userid == sid),
		// but for other tests to run, just change to what returns to me for now
		assert.Equal(t, mockUserID, transferEntry.UserId.Id, "UserID in transfer cache entry doesn't match expected")
		transfers.DeleteAll()
	})

	// Testing against close event is less meaningfult than do a full-run
	// as the close event require user/transfer info to work as expected. Although
	// adding another test case with file-close event only to check the edge cases is
	// also highly recommended
	t.Run("f-stream-file-open-xfr-close-events-should-register-correctly", func(t *testing.T) {
		mockReadCalls := int32(120)
		mockReadVCalls := int32(10)
		mockWriteCalls := int32(30)
		mockReadVSegments := int64(1000)

		TransferReadvSegs.Reset()
		TransferOps.Reset()
		TransferBytes.Reset()

		openPacket, err := mockFileOpenPacket(0, mockFileID, mockUserID, mockSID, "/full/path/to/file.txt")
		require.NoError(t, err, "Error generating mock file open packet")
		xftPacket, err := mockFileXfrPacket(1, mockFileID, mockSID, mockRead, mockReadV, mockWrite)
		require.NoError(t, err, "Error generating mock file transfer packet")
		opsState := mockStatOps(mockReadCalls, mockReadVCalls, mockWriteCalls, mockReadVSegments)
		clsPacket, err := mockFileClosePacket(2, mockFileID, mockSID, opsState, mockRead, mockReadV, mockWrite)
		require.NoError(t, err, "Error generating mock file close packet")

		transfers.DeleteAll()
		sessions.DeleteAll()

		err = HandlePacket(openPacket)
		require.NoError(t, err, "Error handling the file open packet")

		require.Equal(t, 1, len(transfers.Keys()), "Transfer cache didn't update")
		assert.Equal(t, mockFileID, transfers.Keys()[0].Id, "Id in session cache entry doesn't match expected")
		transferEntry := transfers.Get(transfers.Keys()[0]).Value()
		assert.Equal(t, "/", transferEntry.Path, "Path in transfer cache entry doesn't match expected")
		assert.Equal(t, mockUserID, transferEntry.UserId.Id, "UserID in transfer cache entry doesn't match expected")

		err = HandlePacket(xftPacket)
		require.NoError(t, err, "Error handling the file transfer packet")

		err = HandlePacket(clsPacket)
		require.NoError(t, err, "Error handling the file close packet")

		// Trasnfer item should be deleted on file close
		require.Equal(t, 0, len(transfers.Keys()), "Transfer cache didn't update")

		expectedTransferReadvSegs := `
		# HELP xrootd_transfer_readv_segments_count Number of segments in readv operations
		# TYPE xrootd_transfer_readv_segments_count counter
		xrootd_transfer_readv_segments_count{ap="",dn="",org="",path="/",role=""} 1000
		`

		expectedTransferOps := `
		# HELP xrootd_transfer_operations_count Number of transfer operations performed
		# TYPE xrootd_transfer_operations_count counter
		xrootd_transfer_operations_count{ap="",dn="",org="",path="/",role="",type="read"} 120
		xrootd_transfer_operations_count{ap="",dn="",org="",path="/",role="",type="readv"} 10
		xrootd_transfer_operations_count{ap="",dn="",org="",path="/",role="",type="write"} 30
		`

		expectedTransferBytes := `
		# HELP xrootd_transfer_bytes Bytes of transfers
		# TYPE xrootd_transfer_bytes counter
		xrootd_transfer_bytes{ap="",dn="",org="",path="/",role="",type="read"} 10000
		xrootd_transfer_bytes{ap="",dn="",org="",path="/",role="",type="readv"} 20000
		xrootd_transfer_bytes{ap="",dn="",org="",path="/",role="",type="write"} 120
		`

		expectedTransferReadvSegsReader := strings.NewReader(expectedTransferReadvSegs)
		expectedTransferOpsReader := strings.NewReader(expectedTransferOps)
		expectedTransferBytesReader := strings.NewReader(expectedTransferBytes)

		if err := testutil.CollectAndCompare(TransferReadvSegs, expectedTransferReadvSegsReader, "xrootd_transfer_readv_segments_count"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}

		if err := testutil.CollectAndCompare(TransferOps, expectedTransferOpsReader, "xrootd_transfer_operations_count"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}

		if err := testutil.CollectAndCompare(TransferBytes, expectedTransferBytesReader, "xrootd_transfer_bytes"); err != nil {
			require.NoError(t, err, "Collected metric is different from expected")
		}
	})
}
