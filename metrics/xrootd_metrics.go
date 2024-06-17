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

package metrics

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

type (
	SummaryStatType string
	UserId          struct {
		Id uint32
	}

	// userid as in XRootD message info field
	XrdUserId struct {
		Prot string
		User string
		Pid  int
		Sid  int
		Host string
	}

	UserRecord struct {
		AuthenticationProtocol string
		User                   string
		DN                     string
		Role                   string
		Org                    string
		Groups                 []string
		Project                string
	}

	FileId struct {
		Id uint32
	}

	FileRecord struct {
		UserId     UserId
		Path       string
		ReadOps    uint32
		ReadvOps   uint32
		WriteOps   uint32
		ReadvSegs  uint64
		ReadBytes  uint64
		ReadvBytes uint64
		WriteBytes uint64
	}

	PathList struct {
		Paths []string
	}

	XrdXrootdMonHeader struct {
		Code byte   // = | d | f | g | i | p | r | t | u | x
		Pseq byte   // packet sequence
		Plen uint16 // packet length
		Stod int32  // Unix time at Server start
	}

	XrdXrootdMonMap struct {
		Hdr    XrdXrootdMonHeader
		Dictid uint32
		Info   []byte
	}

	recTval byte

	XrdXrootdMonFileHdr struct {
		RecType recTval
		RecFlag byte
		RecSize int16
		FileId  uint32
		UserId  uint32
		NRecs0  int16
		NRecs1  int16
	}

	XrdXrootdMonFileTOD struct {
		Hdr  XrdXrootdMonFileHdr
		TBeg int32
		TEnd int32
		SID  int64
	}

	XrdXrootdMonFileLFN struct {
		User uint32
		Lfn  [1032]byte
	}

	XrdXrootdMonFileOPN struct {
		Hdr XrdXrootdMonFileHdr
		Fsz int64
		Ufn XrdXrootdMonFileLFN
	}

	XrdXrootdMonStatXFR struct {
		Read  int64 // Bytes read from file using read()
		Readv int64 // Bytes read from file using readv()
		Write int64 // Bytes written to file
	}

	XrdXrootdMonFileXFR struct {
		Hdr XrdXrootdMonFileHdr // Header with recType == isXfr
		Xfr XrdXrootdMonStatXFR
	}

	XrdXrootdMonStatOPS struct { // 48B
		Read  int32 // Number of read() calls
		Readv int32 // Number of readv() calls
		Write int32 // Number of write() calls
		RsMin int16 // Smallest readv() segment count
		RsMax int16 // Largest readv() segment count
		Rsegs int64 // Number of readv() segments
		RdMin int32 // Smallest read() request size
		RdMax int32 // Largest read() request size
		RvMin int32 // Smallest readv() request size
		RvMax int32 // Largest readv() request size
		WrMin int32 // Smallest write() request size
		WrMax int32 // Largest write() request size
	}

	// XrdXrootdMonFileCLS represents a variable length structure and
	// includes other structures that are "Always present" or "OPTIONAL".
	// The OPTIONAL parts are not included here as they require more context.
	XrdXrootdMonFileCLS struct {
		Hdr XrdXrootdMonFileHdr // Always present
		Xfr XrdXrootdMonStatXFR // Always present
		Ops XrdXrootdMonStatOPS // OPTIONAL
		// Ssq XrdXrootdMonStatSSQ // OPTIONAL, not implemented here yet
	}

	XrdXrootdMonGS struct {
		Hdr  XrdXrootdMonHeader
		TBeg int   // UNIX time of first entry
		TEnd int   // UNIX time of last entry
		SID  int64 // Provider identification
	}

	// Cache g-stream: https://xrootd.slac.stanford.edu/doc/dev56/xrd_monitoring.htm#_Toc138968526
	CacheGS struct {
		AccessCnt   uint32 `json:"access_cnt"`
		AttachT     int64  `json:"attach_t"`
		ByteBypass  int64  `json:"b_bypass"`
		ByteHit     int64  `json:"b_hit"`
		ByteMiss    int64  `json:"b_miss"`
		BlkSize     int    `json:"blk_size"`
		DetachT     int64  `json:"detach_t"`
		Event       string `json:"event"`
		Lfn         string `json:"lfn"`
		NBlocks     int    `json:"n_blks"`
		NBlocksDone int    `json:"n_blks_done"`
		NCksErrs    int    `json:"n_cks_errs"`
		Size        int64  `json:"size"`
	}

	// Throttle plug-in g-stream
	ThrottleGS struct {
		IOWaitTime float64 `json:"io_wait"`
		IOActive   int     `json:"io_active"`
		IOTotal    int     `json:"io_total"`
	}

	CacheAccessStat struct {
		Hit    int64
		Miss   int64
		Bypass int64
	}

	SummaryPathStat struct {
		Id    string `xml:"id,attr"`
		Lp    string `xml:"lp"`   // The minimally reduced logical file system path i.e. top-level namespace
		Free  int    `xml:"free"` // Kilobytes available
		Total int    `xml:"tot"`  // Kilobytes allocated
	}

	SummaryPath struct {
		Idx   int               `xml:",chardata"`
		Stats []SummaryPathStat `xml:"stats"`
	}

	SummaryCacheStore struct {
		Size int `xml:"size"`
		Used int `xml:"used"`
		Min  int `xml:"min"`
		Max  int `xml:"max"`
	}

	SummaryCacheMemory struct {
		Size int `xml:"size"`
		Used int `xml:"used"`
		Wq   int `xml:"wq"`
	}

	SummaryStat struct {
		Id      SummaryStatType    `xml:"id,attr"`
		Total   int                `xml:"tot"`
		In      int                `xml:"in"`
		Out     int                `xml:"out"`
		Threads int                `xml:"threads"`
		Idle    int                `xml:"idle"`
		Paths   SummaryPath        `xml:"paths"` // For Oss Summary Data
		Store   SummaryCacheStore  `xml:"store"`
		Memory  SummaryCacheMemory `xml:"mem"`
	}

	SummaryStatistics struct {
		Version string        `xml:"ver,attr"`
		Program string        `xml:"pgm,attr"`
		Stats   []SummaryStat `xml:"stats"`
	}
)

// XrdXrootdMonFileHdr
// Ref: https://github.com/xrootd/xrootd/blob/f3b2e86b9b80bb35f97dd4ad30c4cd5904902a4c/src/XrdXrootd/XrdXrootdMonData.hh#L173
const (
	isClose recTval = iota
	isOpen
	isTime
	isXfr
	isDisc
)

const (
	XROOTD_MON_PIDSHFT = int64(56)
	XROOTD_MON_PIDMASK = int64(0xff)
)

// Summary data types
const (
	LinkStat  SummaryStatType = "link"  // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653739
	SchedStat SummaryStatType = "sched" // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653745
	OssStat   SummaryStatType = "oss"   // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653741
	CacheStat SummaryStatType = "cache" // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653733
)

var (
	PacketsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_monitoring_packets_received",
		Help: "The total number of monitoring UDP packets received",
	})

	TransferReadvSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_readv_segments_count",
		Help: "Number of segments in readv operations",
	}, []string{"path", "ap", "dn", "role", "org", "proj"})

	TransferOps = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_operations_count",
		Help: "Number of transfer operations performed",
	}, []string{"path", "ap", "dn", "role", "org", "proj", "type"})

	TransferBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_bytes",
		Help: "Bytes of transfers",
	}, []string{"path", "ap", "dn", "role", "org", "proj", "type"})

	Threads = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_sched_thread_count",
		Help: "Number of scheduler threads",
	}, []string{"state"})

	Connections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_connection_count",
		Help: "Aggregate number of server connections",
	})

	BytesXfer = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_server_bytes",
		Help: "Number of bytes read into the server",
	}, []string{"direction"})

	StorageVolume = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_storage_volume_bytes",
		Help: "Storage volume usage on the server",
	}, []string{"ns", "type", "server_type"}) // type: total/free; server_type: origin/cache

	CacheAccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_access_bytes",
		Help: "Number of bytes the data requested is in the cache or not",
	}, []string{"path", "type"}) // type: hit/miss/bypass

	ServerTotalIO = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_io_total",
		Help: "Total storage operations in origin/cache server",
	})

	ServerActiveIO = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_server_io_active",
		Help: "Number of ongoing storage operations in origin/cache server",
	})

	ServerIOWaitTime = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_io_wait_time",
		Help: "The aggregate time spent in storage operations in origin/cache server",
	})

	lastStats SummaryStat

	lastTotalIO  int     // The last total IO value
	lastWaitTime float64 // The last IO wait time

	// Maps the connection identifier with a user record
	sessions = ttlcache.New[UserId, UserRecord](ttlcache.WithTTL[UserId, UserRecord](24 * time.Hour))
	// Maps a userid to a connection identifier.  NOTE: due to https://github.com/xrootd/xrootd/issues/2133,
	// this may not be a unique map.
	userids = ttlcache.New[XrdUserId, UserId](ttlcache.WithTTL[XrdUserId, UserId](24 * time.Hour))
	// Maps a file identifier with a file record
	transfers    = ttlcache.New[FileId, FileRecord](ttlcache.WithTTL[FileId, FileRecord](24 * time.Hour))
	monitorPaths []PathList
)

// Set up listening and parsing xrootd monitoring UDP packets into prometheus
//
// The `ctx` is the context for listening to server shutdown event in order to cleanup internal cache eviction
func ConfigureMonitoring(ctx context.Context, egrp *errgroup.Group) (int, error) {
	monitorPaths = make([]PathList, 0)
	for _, monpath := range param.Monitoring_AggregatePrefixes.GetStringSlice() {
		monitorPaths = append(monitorPaths, PathList{Paths: strings.Split(path.Clean(monpath), "/")})
	}

	lower := param.Monitoring_PortLower.GetInt()
	higher := param.Monitoring_PortHigher.GetInt()

	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
	var conn *net.UDPConn
	var err error
	for portAttempt := lower; portAttempt < higher; portAttempt++ {
		addr.Port = portAttempt
		conn, err = net.ListenUDP("udp", &addr)
		if err == nil {
			break
		}
	}
	if conn == nil {
		if err != nil {
			return -1, err
		}
		return -1, errors.New("Failed to create a UDP listening socket for monitoring")
	}

	// Set the read buffer size to 1 MB
	err = conn.SetReadBuffer(1024 * 1024)
	if err != nil {
		return -1, err
	}

	// Start ttl cache automatic eviction of expired items
	go sessions.Start()
	go userids.Start()
	go transfers.Start()

	// Stop automatic eviction at shutdown
	egrp.Go(func() error {
		<-ctx.Done()
		conn.Close() // This will cause an net.ErrClosed in the goroutine below
		sessions.Stop()
		userids.Stop()
		transfers.Stop()
		log.Infoln("Xrootd metrics cache eviction has been stopped")
		return nil
	})

	go func() {
		var buf [65536]byte
		for {
			// TODO: actually parse the UDP packets
			plen, _, err := conn.ReadFromUDP(buf[:])
			if errors.Is(err, net.ErrClosed) {
				return
			} else if err != nil {
				log.Errorln("Failed to read from UDP connection", err)
				continue
			}
			PacketsReceived.Inc()
			if err = HandlePacket(buf[:plen]); err != nil {
				log.Errorln("Failed to handle packet:", err)
			}
		}
	}()

	return addr.Port, nil
}

func computePrefix(inputPath string, monitorPaths []PathList) string {
	if len(monitorPaths) == 0 {
		return "/"
	}

	segments := strings.Split(path.Clean(inputPath), "/")

	maxlen := 0
	for _, pathList := range monitorPaths {
		if len(pathList.Paths) > len(segments) {
			continue
		}
		for idx, segment := range pathList.Paths {
			if len(segments) <= idx {
				break
			}
			if segments[idx] != segment && segment != "*" {
				break
			}
			if idx > maxlen {
				maxlen = idx
			}
		}
	}
	if maxlen == 0 {
		return "/"
	}

	result := ""
	for idx := 1; idx < maxlen+1; idx++ {
		result += "/" + segments[idx]
	}
	return path.Clean(result)
}

func GetSIDRest(info []byte) (xrdUserId XrdUserId, rest string, err error) {
	log.Debugln("GetSIDRest inputs:", string(info))
	infoSplit := strings.SplitN(string(info), "\n", 2)
	if len(infoSplit) == 1 {
		err = errors.New("Unable to parse SID")
		return
	}
	rest = infoSplit[1]

	xrdUserId, err = ParseXrdUserId(infoSplit[0])
	return
}

func ParseXrdUserId(userid string) (xrdUserId XrdUserId, err error) {
	// Expected format: prot/user.id:sid@clientHost
	sidInfo := strings.SplitN(userid, ":", 2)
	if len(sidInfo) == 1 {
		err = errors.New("Unable to parse valid user ID - missing ':' delimiter")
		return
	}

	// Parse server ID and client hostname,
	// Form: 82215220691948@localhost
	sidAtHostname := sidInfo[1]
	sidAtHostnameInfo := strings.SplitN(sidAtHostname, "@", 2)
	if len(sidAtHostnameInfo) == 1 {
		err = errors.New("Unable to parse valid server ID - missing '@' delimiter")
		return
	}
	sid, err := strconv.Atoi(sidAtHostnameInfo[0])
	if err != nil {
		err = errors.Wrap(err, "Unable to parse valid server ID")
		return
	}

	// Parse prot/user.id
	protUserIdInfo := strings.SplitN(sidInfo[0], "/", 2)
	if len(protUserIdInfo) == 1 {
		err = errors.New("Unable to parse user ID - missing '/' delimiter")
		return
	}

	// Parse user.id; assume user may contain multiple '.' characters
	lastIdx := strings.LastIndex(protUserIdInfo[1], ".")
	if lastIdx == -1 {
		err = errors.New("Unable to parse user ID - missing '.' delimiter")
		return
	}
	pid, err := strconv.Atoi(protUserIdInfo[1][lastIdx+1 : len(protUserIdInfo[1])])
	if err != nil {
		err = errors.Wrap(err, "Unsable to parse PID as integer")
		return
	}

	// Finally, fill in our userid struct
	xrdUserId.Prot = protUserIdInfo[0]
	xrdUserId.User = protUserIdInfo[1][:lastIdx]
	xrdUserId.Pid = pid
	xrdUserId.Sid = sid
	xrdUserId.Host = string(sidAtHostname[1])
	return
}

func ParseTokenAuth(tokenauth string) (userId UserId, record UserRecord, err error) {
	record.AuthenticationProtocol = "ztn"
	foundUc := false
	for _, pair := range strings.Split(tokenauth, "&") {
		keyVal := strings.SplitN(pair, "=", 2)
		if len(keyVal) != 2 {
			continue
		}
		switch keyVal[0] {
		case "Uc":
			var id int
			id, err = strconv.Atoi(keyVal[1])
			if err != nil {
				err = errors.Wrap(err, "Unable to parse user ID to integer")
				return
			}
			if id < 0 || id > math.MaxUint32 {
				err = errors.Errorf("Provided ID, %d, is not a valid uint32", id)
				return
			}
			userId.Id = uint32(id)
			foundUc = true
		case "s":
			record.DN = keyVal[1]
		case "un":
			record.User = keyVal[1]
		case "o":
			record.Org = keyVal[1]
		case "r":
			record.Role = keyVal[1]
		case "g":
			record.Groups = strings.Split(keyVal[1], " ")
		}
	}
	if !foundUc {
		err = errors.New("The user ID was not provided in the token record")
		return
	}
	return
}

func ParseFileHeader(packet []byte) (XrdXrootdMonFileHdr, error) {
	if len(packet) < 8 {
		return XrdXrootdMonFileHdr{}, fmt.Errorf("Passed header of size %v which is below the minimum header size of 8 bytes", len(packet))
	}
	fileHdr := XrdXrootdMonFileHdr{
		RecType: recTval(packet[0]),
		RecFlag: packet[1],
		RecSize: int16(binary.BigEndian.Uint16(packet[2:4])),
		FileId:  binary.BigEndian.Uint32(packet[4:8]),
		UserId:  binary.BigEndian.Uint32(packet[4:8]),
		NRecs0:  int16(binary.BigEndian.Uint16(packet[4:6])),
		NRecs1:  int16(binary.BigEndian.Uint16(packet[6:8])),
	}
	return fileHdr, nil
}

func NullTermToString(nullTermBytes []byte) (str string) {
	idx := bytes.IndexByte(nullTermBytes, '\x00')
	if idx == -1 {
		return ""
	}
	return string(nullTermBytes[0:idx])
}

func HandlePacket(packet []byte) error {
	// XML '<' character indicates a summary packet
	if len(packet) > 0 && packet[0] == '<' {
		return HandleSummaryPacket(packet)
	}

	if len(packet) < 8 {
		return errors.New("Packet is too small to be valid XRootD monitoring packet")
	}
	var header XrdXrootdMonHeader
	header.Code = packet[0]
	header.Pseq = packet[1]
	header.Plen = binary.BigEndian.Uint16(packet[2:4])
	header.Stod = int32(binary.BigEndian.Uint32(packet[4:8]))

	// For =, p, and x record-types, this is always 0
	// For i, T, u, and U , this is a connection ID
	// For d, this is a file ID.
	dictid := binary.BigEndian.Uint32(packet[8:12])

	switch header.Code {
	case 'd':
		log.Debug("HandlePacket: Received a file-open packet")
		if len(packet) < 12 {
			return errors.New("Packet is too small to be valid file-open packet")
		}
		fileid := FileId{Id: dictid}
		xrdUserId, rest, err := GetSIDRest(packet[12:])
		if err != nil {
			return errors.Wrapf(err, "Failed to parse XRootD monitoring packet")
		}
		path := computePrefix(rest, monitorPaths)
		if useridItem := userids.Get(xrdUserId); useridItem != nil {
			transfers.Set(fileid, FileRecord{UserId: useridItem.Value(), Path: path}, ttlcache.DefaultTTL)
		}
	case 'f':
		log.Debug("HandlePacket: Received a f-stream packet")
		// sizeof(XrdXrootdMonHeader) + sizeof(XrdXrootdMonFileTOD)
		if len(packet) < 8+24 {
			return errors.New("Packet is too small to be a valid f-stream packet")
		}
		firstHeaderSize := binary.BigEndian.Uint16(packet[10:12])
		if firstHeaderSize < 24 {
			return fmt.Errorf("First entry in f-stream packet is %v bytes, smaller than the minimum XrdXrootdMonFileTOD size of 24 bytes", firstHeaderSize)
		}
		offset := uint32(firstHeaderSize + 8)
		bytesRemain := header.Plen - uint16(offset)
		for bytesRemain > 0 {
			fileHdr, err := ParseFileHeader(packet[offset : offset+8])
			if err != nil {
				return err
			}
			switch fileHdr.RecType {
			case isClose: // XrdXrootdMonFileHdr::isClose
				log.Debugln("Received a f-stream file-close packet of size ",
					fileHdr.RecSize)
				fileId := FileId{Id: fileHdr.FileId}
				xferRecord := transfers.Get(fileId)
				transfers.Delete(fileId)
				labels := prometheus.Labels{
					"path": "/",
					"ap":   "",
					"dn":   "",
					"role": "",
					"org":  "",
					"proj": "",
				}
				var oldReadvSegs uint64 = 0
				var oldReadOps uint32 = 0
				var oldReadvOps uint32 = 0
				var oldWriteOps uint32 = 0
				var oldReadBytes uint64 = 0
				var oldReadvBytes uint64 = 0
				var oldWriteBytes uint64 = 0
				if xferRecord != nil {
					userRecord := sessions.Get(xferRecord.Value().UserId)
					sessions.Delete(xferRecord.Value().UserId)
					labels["path"] = xferRecord.Value().Path
					if userRecord != nil {
						labels["ap"] = userRecord.Value().AuthenticationProtocol
						labels["dn"] = userRecord.Value().DN
						labels["role"] = userRecord.Value().Role
						labels["org"] = userRecord.Value().Org
						labels["proj"] = userRecord.Value().Project
					}
					oldReadvSegs = xferRecord.Value().ReadvSegs
					oldReadOps = xferRecord.Value().ReadOps
					oldReadvOps = xferRecord.Value().ReadvOps
					oldWriteOps = xferRecord.Value().WriteOps
					oldReadBytes = xferRecord.Value().ReadBytes
					oldReadvBytes = xferRecord.Value().ReadvBytes
					oldWriteBytes = xferRecord.Value().WriteBytes
				}
				if fileHdr.RecFlag&0x02 == 0x02 { // XrdXrootdMonFileHdr::hasOPS
					// sizeof(XrdXrootdMonFileHdr) + sizeof(XrdXrootdMonStatXFR)
					opsOffset := uint32(8 + 24)
					counter := TransferReadvSegs.With(labels)
					counter.Add(float64(int64(binary.BigEndian.Uint64(
						packet[offset+opsOffset+16:offset+opsOffset+24]) -
						oldReadvSegs)))
					labels["type"] = "read"
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset:offset+opsOffset+4]) -
						oldReadOps)))
					labels["type"] = "readv"
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset+4:offset+opsOffset+8]) -
						oldReadvOps)))
					labels["type"] = "write"
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset+8:offset+opsOffset+12]) -
						oldWriteOps)))
				}
				xfrOffset := uint32(8) // sizeof(XrdXrootdMonFileHdr)
				labels["type"] = "read"
				counter := TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset+xfrOffset:offset+xfrOffset+8]) -
					oldReadBytes)))
				labels["type"] = "readv"
				counter = TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset+xfrOffset+8:offset+xfrOffset+16]) -
					oldReadvBytes)))
				labels["type"] = "write"
				counter = TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset+xfrOffset+16:offset+xfrOffset+24]) -
					oldWriteBytes)))
			case isOpen: // XrdXrootdMonFileHdr::isOpen
				log.Debug("MonPacket: Received a f-stream file-open packet")
				fileid := FileId{Id: fileHdr.FileId}
				path := ""
				userId := UserId{}
				if fileHdr.RecFlag&0x01 == 0x01 { // hasLFN
					lfnSize := uint32(fileHdr.RecSize - 20)
					lfn := NullTermToString(packet[offset+20 : offset+lfnSize+20])
					// path has been difined
					path = computePrefix(lfn, monitorPaths)
					log.Debugf("MonPacket: User LFN %v matches prefix %v",
						lfn, path)
					// UserId is part of LFN
					userId = UserId{Id: binary.BigEndian.Uint32(packet[offset+16 : offset+20])}
				}
				transfers.Set(fileid, FileRecord{UserId: userId, Path: path},
					ttlcache.DefaultTTL)
			case isTime: // XrdXrootdMonFileHdr::isTime
				log.Debug("MonPacket: Received a f-stream time packet")
			case isXfr: // XrdXrootdMonFileHdr::isXfr
				log.Debug("MonPacket: Received a f-stream transfer packet")
				// NOTE: There's a lot to do here.  These records would allow us to
				// capture partial file transfers or emulate a close on timeout.
				// For now, we'll record the data but don't use it.
				fileid := FileId{Id: fileHdr.FileId}
				item := transfers.Get(fileid)
				var record FileRecord
				readBytes := binary.BigEndian.Uint64(packet[offset+8 : offset+16])
				readvBytes := binary.BigEndian.Uint64(packet[offset+16 : offset+24])
				writeBytes := binary.BigEndian.Uint64(packet[offset+24 : offset+32])

				labels := prometheus.Labels{
					"path": "/",
					"ap":   "",
					"dn":   "",
					"role": "",
					"org":  "",
					"proj": "",
				}

				if item != nil {
					record = item.Value()
					userRecord := sessions.Get(record.UserId)
					labels["path"] = record.Path
					if userRecord != nil {
						labels["ap"] = userRecord.Value().AuthenticationProtocol
						labels["dn"] = userRecord.Value().DN
						labels["role"] = userRecord.Value().Role
						labels["org"] = userRecord.Value().Org
						labels["proj"] = userRecord.Value().Project
					}
				}

				// We record those metrics to make sure they are properly populated with initial
				// values, or the file close handler will only populate them by the difference, not
				// the total
				labels["type"] = "read"
				counter := TransferBytes.With(labels)
				incBy := int64(readBytes - record.ReadBytes)
				if incBy >= 0 {
					counter.Add(float64(incBy))
				} else {
					log.Debug("File-transfer ReadBytes is less than previous value")
				}
				labels["type"] = "readv"
				counter = TransferBytes.With(labels)
				incBy = int64(readvBytes - record.ReadvBytes)
				if incBy >= 0 {
					counter.Add(float64(incBy))
				} else {
					log.Debug("File-transfer ReadVBytes is less than previous value")
				}
				labels["type"] = "write"
				counter = TransferBytes.With(labels)
				incBy = int64(writeBytes - record.WriteBytes)
				if incBy >= 0 {
					counter.Add(float64(incBy))
				} else {
					log.Debug("File-transfer WriteByte is less than previous value")
				}
				record.ReadBytes = readBytes
				record.ReadvBytes = readvBytes
				record.WriteBytes = writeBytes
				transfers.Set(fileid, record, ttlcache.DefaultTTL)

			case isDisc: // XrdXrootdMonFileHdr::isDisc
				log.Debug("MonPacket: Received a f-stream disconnect packet")
				userId := UserId{Id: fileHdr.UserId}
				if session := sessions.Get(userId); session != nil {
					sessions.Delete(userId)
				}
			default:
				log.Debug("MonPacket: Received an unhandled file monitoring packet "+
					"of type ", fileHdr.RecType)
			}

			bytesRemain -= uint16(fileHdr.RecSize)
			offset += uint32(fileHdr.RecSize)
		}
	case 'g':
		log.Debug("HandlePacket: Received a g-stream packet")
		if len(packet) < 8+16 {
			return errors.New("Packet is too small to be a valid g-stream packet")
		}
		gs := XrdXrootdMonGS{
			Hdr:  header,
			TBeg: int(binary.BigEndian.Uint32(packet[8:12])),
			TEnd: int(binary.BigEndian.Uint32(packet[12:16])),
			SID:  int64(binary.BigEndian.Uint64(packet[16:24])),
		}
		// Extract the provider’s identifier
		providerID := (gs.SID >> XROOTD_MON_PIDSHFT) & XROOTD_MON_PIDMASK
		detail := NullTermToString(packet[24:])
		strJsons := strings.Split(detail, "\n")
		if providerID == 'C' { // pfc: Cache monitoring info
			log.Debug("HandlePacket: Received g-stream packet is from cache")
			aggCacheStat := make(map[string]*CacheAccessStat)
			for _, js := range strJsons {
				cacheStat := CacheGS{}
				if err := json.Unmarshal([]byte(js), &cacheStat); err != nil {
					return errors.Wrap(err, "failed to parse cache stat json. Raw data is "+string(js))
				}

				prefix := computePrefix(cacheStat.Lfn, monitorPaths)
				if aggCacheStat[prefix] == nil {
					aggCacheStat[prefix] = &CacheAccessStat{
						Hit:    cacheStat.ByteHit,
						Miss:   cacheStat.ByteMiss,
						Bypass: cacheStat.ByteBypass,
					}
				} else {
					aggCacheStat[prefix].Hit += cacheStat.ByteHit
					aggCacheStat[prefix].Miss += cacheStat.ByteMiss
					aggCacheStat[prefix].Bypass += cacheStat.ByteBypass
				}
			}
			for prefix, stat := range aggCacheStat {
				// For hit, miss, bypass, each packet only records the buffer
				// between last sent and now, so we need to add them
				CacheAccess.WithLabelValues(prefix, "hit").Add(float64(stat.Hit))
				CacheAccess.WithLabelValues(prefix, "miss").Add(float64(stat.Miss))
				CacheAccess.WithLabelValues(prefix, "bypass").Add(float64(stat.Bypass))
			}
		} else if providerID == 'R' { // IO activity from the throttle plugin
			log.Debug("HandlePacket: Received g-stream packet is from the throttle plugin")
			for _, js := range strJsons {
				throttleGS := ThrottleGS{}
				if err := json.Unmarshal([]byte(js), &throttleGS); err != nil {
					return errors.Wrap(err, "failed to parse throttle plugin stat json. Raw data is "+string(js))
				}
				totalIOInc := 0
				if totalIOInc = throttleGS.IOTotal - lastTotalIO; totalIOInc < 0 {
					totalIOInc = 0
				}
				lastTotalIO = throttleGS.IOTotal

				waitTimeInc := 0.0
				if waitTimeInc = throttleGS.IOWaitTime - lastWaitTime; waitTimeInc < 0 {
					waitTimeInc = 0
				}
				lastWaitTime = throttleGS.IOWaitTime

				ServerTotalIO.Add(float64(totalIOInc))
				ServerActiveIO.Set(float64(throttleGS.IOActive))
				ServerIOWaitTime.Add(waitTimeInc)
			}
		}

	case 'i':
		log.Debug("HandlePacket: Received an appinfo packet")
		infoSize := uint32(header.Plen - 12)
		if xrdUserId, appinfo, err := GetSIDRest(packet[12 : 12+infoSize]); err == nil {
			if userids.Has(xrdUserId) {
				userId := userids.Get(xrdUserId).Value()
				if sessions.Has(userId) {
					existingRec := sessions.Get(userId).Value()
					existingRec.Project = appinfo
					sessions.Set(userId, existingRec, ttlcache.DefaultTTL)
				} else {
					sessions.Set(userId, UserRecord{Project: appinfo}, ttlcache.DefaultTTL)
				}
			}
		} else {
			return err
		}
	case 'u':
		log.Debug("HandlePacket: Received a user login packet")
		infoSize := uint32(header.Plen - 12)
		if xrdUserId, auth, err := GetSIDRest(packet[12 : 12+infoSize]); err == nil {
			var record UserRecord
			for _, pair := range strings.Split(auth, "&") {
				keyVal := strings.SplitN(pair, "=", 2)
				if len(keyVal) != 2 {
					continue
				}
				switch keyVal[0] {
				case "n":
					record.DN = keyVal[1]
				case "p":
					record.AuthenticationProtocol = keyVal[1]
				case "o":
					record.Org = keyVal[1]
				case "r":
					record.Role = keyVal[1]
				case "g":
					record.Groups = strings.Split(keyVal[1], " ")
				}
			}
			if len(record.AuthenticationProtocol) > 0 {
				record.User = xrdUserId.User
			}
			sessions.Set(UserId{Id: dictid}, record, ttlcache.DefaultTTL)
			userids.Set(xrdUserId, UserId{Id: dictid}, ttlcache.DefaultTTL)
		} else {
			return err
		}
	case 'T':
		log.Debug("HandlePacket: Received a token info packet")
		infoSize := uint32(header.Plen - 12)
		if _, tokenauth, err := GetSIDRest(packet[12 : 12+infoSize]); err == nil {
			userId, userRecord, err := ParseTokenAuth(tokenauth)
			if err != nil {
				return err
			}
			sessions.Set(userId, userRecord, ttlcache.DefaultTTL)
		} else {
			return err
		}
	default:
		log.Debugf("HandlePacket: Received an unhandled monitoring packet of type %v", header.Code)
	}

	return nil

}

// Unlike the highly-compressed binary format that is the detailed monitoring, the summary monitoring
// is a mostly-compliant chunk of XML.  I copy below the pretty-printed version of a sample packet:
/*
   <statistics tod="1687524138" ver="v5.2.0" src="hcc-briantest7.unl.edu:8443" tos="1687523538" pgm="xrootd" ins="anon" pid="3852923" site="hcc-briantest7.unl.edu">
  <stats id="info">
    <host>hcc-briantest7.unl.edu</host>
    <port>8443</port>
    <name>anon</name>
  </stats>
  <stats id="buff">
    <reqs>2</reqs>
    <mem>1049600</mem>
    <buffs>2</buffs>
    <adj>0</adj>
    <xlreqs>0</xlreqs>
    <xlmem>0</xlmem>
    <xlbuffs>0</xlbuffs>
  </stats>
  <stats id="link">
    <num>0</num>
    <maxn>1</maxn>
    <tot>1</tot>
    <in>474</in>
    <out>1117</out>
    <ctime>0</ctime>
    <tmo>0</tmo>
    <stall>0</stall>
    <sfps>0</sfps>
  </stats>
  <stats id="poll">
    <att>0</att>
    <en>1</en>
    <ev>1</ev>
    <int>0</int>
  </stats>
  <stats id="proc">
    <usr>
      <s>0</s>
      <u>42946</u>
    </usr>
    <sys>
      <s>0</s>
      <u>52762</u>
    </sys>
  </stats>
  <stats id="xrootd">
    <num>1</num>
    <ops>
      <open>1</open>
      <rf>0</rf>
      <rd>1</rd>
      <pr>0</pr>
      <rv>0</rv>
      <rs>0</rs>
      <wv>0</wv>
      <ws>0</ws>
      <wr>0</wr>
      <sync>0</sync>
      <getf>0</getf>
      <putf>0</putf>
      <misc>2</misc>
    </ops>
    <sig>
      <ok>0</ok>
      <bad>0</bad>
      <ign>0</ign>
    </sig>
    <aio>
      <num>0</num>
      <max>0</max>
      <rej>0</rej>
    </aio>
    <err>0</err>
    <rdr>0</rdr>
    <dly>0</dly>
    <lgn>
      <num>0</num>
      <af>0</af>
      <au>0</au>
      <ua>0</ua>
    </lgn>
  </stats>
  <stats id="ofs">
    <role>server</role>
    <opr>0</opr>
    <opw>0</opw>
    <opp>0</opp>
    <ups>0</ups>
    <han>0</han>
    <rdr>0</rdr>
    <bxq>0</bxq>
    <rep>0</rep>
    <err>0</err>
    <dly>0</dly>
    <sok>0</sok>
    <ser>0</ser>
    <tpc>
      <grnt>0</grnt>
      <deny>0</deny>
      <err>0</err>
      <exp>0</exp>
    </tpc>
  </stats>
  <stats id="oss" v="2">
    <paths>1<stats id="0"><lp>"/test"</lp><rp>"/run/user/1221/pelican/export/test"</rp><tot>1562624</tot><free>1529424</free><ino>786432</ino><ifr>786405</ifr></stats></paths>
    <space>0</space>
  </stats>
  <stats id="sched">
    <jobs>188</jobs>
    <inq>0</inq>
    <maxinq>5</maxinq>
    <threads>7</threads>
    <idle>5</idle>
    <tcr>7</tcr>
    <tde>0</tde>
    <tlimr>0</tlimr>
  </stats>
  <stats id="sgen">
    <as>0</as>
    <et>1</et>
    <toe>1687524138</toe>
  </stats>
</statistics>
*/

func HandleSummaryPacket(packet []byte) error {
	summaryStats := SummaryStatistics{}
	// The cache summary data has a typo where the <hit> tag contains a trailing bracet
	// the causes parsing error. This is a temp fix to correct it. Xrootd v5.7.0 will fix
	// this issue
	re, err := regexp.Compile(`></hits>`)
	if err != nil {
		return errors.Wrap(err, "error compiling regex")
	}

	correctedData := re.ReplaceAll(packet, []byte(`</hits>`))

	if err := xml.Unmarshal(correctedData, &summaryStats); err != nil {
		return errors.Wrap(err, "error unmarshaling summary packet")
	}

	log.Debug("Received a summary statistics packet")
	if summaryStats.Program != "xrootd" {
		// We only care about the xrootd summary packets
		return nil
	}
	for _, stat := range summaryStats.Stats {
		switch stat.Id {

		case LinkStat:
			// When stats tag has id="link", the following definitions are valid:
			// stat.Total: Connections since start-up.
			// stat.In: Bytes received
			// stat.Out: Bytes sent

			// Note that stat.Total is the total connections since the start-up of the servcie
			// So we just want to make sure here that no negative value is present
			incBy := float64(stat.Total - lastStats.Total)
			if stat.Total < lastStats.Total {
				incBy = float64(stat.Total)
			}
			Connections.Add(incBy)
			lastStats.Total = stat.Total

			incBy = float64(stat.In - lastStats.In)
			if stat.In < lastStats.In {
				incBy = float64(stat.In)
			}
			BytesXfer.With(prometheus.Labels{"direction": "rx"}).Add(incBy)
			lastStats.In = stat.In

			incBy = float64(stat.Out - lastStats.Out)
			if stat.Out < lastStats.Out {
				incBy = float64(stat.Out)
			}
			BytesXfer.With(prometheus.Labels{"direction": "tx"}).Add(incBy)
			lastStats.Out = stat.Out
		case SchedStat:
			Threads.With(prometheus.Labels{"state": "idle"}).Set(float64(stat.Idle))
			Threads.With(prometheus.Labels{"state": "running"}).Set(float64(stat.Threads -
				stat.Idle))
		case OssStat: // Oss stat should only appear on origin servers
			for _, pathStat := range stat.Paths.Stats {
				noQuoteLp := strings.Replace(pathStat.Lp, "\"", "", 2)
				// pathStat.Total is in kilobytes but we want to standardize all data to bytes
				StorageVolume.With(prometheus.Labels{"ns": noQuoteLp, "type": "total", "server_type": "origin"}).
					Set(float64(pathStat.Total * 1024))
				StorageVolume.With(prometheus.Labels{"ns": noQuoteLp, "type": "free", "server_type": "origin"}).
					Set(float64(pathStat.Free * 1024))
			}
		case CacheStat:
			cacheStore := stat.Store
			StorageVolume.With(prometheus.Labels{"ns": "/cache", "type": "total", "server_type": "cache"}).
				Set(float64(cacheStore.Size))
			StorageVolume.With(prometheus.Labels{"ns": "/cache", "type": "free", "server_type": "cache"}).
				Set(float64(cacheStore.Size - cacheStore.Used))
		}
	}
	return nil
}
