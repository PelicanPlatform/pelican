package metrics

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type (
	UserId struct {
		Id uint32
	}

	UserRecord struct {
		AuthenticationProtocol string
		DN                     string
		Role                   string
		Org                    string
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
		Code byte
		Pseq byte
		Plen uint16
		Stod uint32
	}

	XrdXrootdMonFileHdr struct {
		RecType byte
		RecFlag byte
		RecSize int16
		FileId  uint32
		UserId  uint32
		NRecs0  int16
		NRecs1  int16
	}

	XrdXrootdMonFileTOD struct {
		Hdr XrdXrootdMonFileHdr
		Beg int32
		End int32
		SID int64
	}

	SummaryStat struct {
		Id string `xml:"id,attr"`
		// Relevant for id="link"
		LinkConnections int `xml:"tot"`
		LinkInBytes     int `xml:"in"`
		LinkOutBytes    int `xml:"out"`
		// Relevant for id="sched"
		Threads     int `xml:"threads"`
		ThreadsIdle int `xml:"idle"`
	}

	SummaryStatistics struct {
		Version string        `xml:"ver,attr"`
		Stats   []SummaryStat `xml:"stats"`
	}
)

var (
	PacketsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_monitoring_packets_received",
		Help: "The total number of monitoring UDP packets received",
	})

	TransferReadvSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_readv_segments_count",
		Help: "Number of segments in readv operations",
	}, []string{"path", "ap", "dn", "role", "org"})

	TransferOps = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_operations_count",
		Help: "Number of transfer operations performed",
	}, []string{"path", "ap", "dn", "role", "org", "type"})

	TransferBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_bytes",
		Help: "Bytes of transfers",
	}, []string{"path", "ap", "dn", "role", "org", "type"})

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

	lastStats SummaryStat

	sessions     = ttlcache.New[UserId, UserRecord](ttlcache.WithTTL[UserId, UserRecord](24 * time.Hour))
	transfers    = ttlcache.New[FileId, FileRecord](ttlcache.WithTTL[FileId, FileRecord](24 * time.Hour))
	monitorPaths []PathList
)

func ConfigureMonitoring() (int, error) {
	lower := viper.GetInt("MonitoringPortLower")
	higher := viper.GetInt("MonitoringPortHigher")

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

	go func() {
		var buf [65536]byte
		for {
			// TODO: actually parse the UDP packets
			plen, _, err := conn.ReadFromUDP(buf[:])
			if err != nil {
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

func ComputePrefix(inputPath string) string {
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

func GetSIDRest(info []byte) (UserId, string, error) {
	log.Debugln("GetSIDRest inputs:", string(info))
	infoSplit := strings.SplitN(string(info), "\n", 2)
	if len(infoSplit) == 1 {
		return UserId{}, "", errors.New("Unable to parse SID")
	}

	sidInfo := strings.Split(string(infoSplit[0]), ":")
	if len(sidInfo) == 1 {
		return UserId{}, "", errors.New("Unable to parse valid SID")
	}
	// form: 82215220691948@localhost
	sidAtHostname := sidInfo[len(sidInfo)-1]
	sidAtHostnameInfo := strings.SplitN(sidAtHostname, "@", 2)
	sid, err := strconv.Atoi(sidAtHostnameInfo[0])
	if err != nil {
		return UserId{}, "", err
	}
	return UserId{Id: uint32(sid)}, string(info[1]), nil
}

func ParseFileHeader(packet []byte) (XrdXrootdMonFileHdr, error) {
	if len(packet) < 8 {
		return XrdXrootdMonFileHdr{}, fmt.Errorf("Passed header of size %v which is below the minimum header size of 8 bytes", len(packet))
	}
	fileHdr := XrdXrootdMonFileHdr{
		RecType: packet[0],
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
	header.Stod = binary.BigEndian.Uint32(packet[4:8])

	switch header.Code {
	case 'd':
		log.Debug("HandlePacket: Received a file-open packet")
		if len(packet) < 12 {
			return errors.New("Packet is too small to be valid file-open packet")
		}
		dictid := binary.BigEndian.Uint32(packet[8:12])
		fileid := FileId{Id: dictid}
		userid, rest, err := GetSIDRest(packet[12:])
		if err != nil {
			return errors.Wrapf(err, "Failed to parse XRootD monitoring packet")
		}
		path := ComputePrefix(rest)
		transfers.Set(fileid, FileRecord{UserId: userid, Path: path}, ttlcache.DefaultTTL)
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
			case 0: // XrdXrootdMonFileHdr::isClose
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
			case 1: // XrdXrootdMonFileHdr::isOpen
				log.Debug("MonPacket: Received a f-stream file-open packet")
				fileid := FileId{Id: fileHdr.FileId}
				path := ""
				if fileHdr.RecFlag&0x01 == 0x01 { // hasLFN
					lfnSize := uint32(fileHdr.RecSize - 20)
					lfn := NullTermToString(packet[offset+20 : offset+lfnSize+20])
					path := ComputePrefix(lfn)
					log.Debugf("MonPacket: User LFN %v matches prefix %v",
						lfn, path)
				}
				userid := UserId{Id: binary.BigEndian.Uint32(packet[offset+16 : offset+20])}
				transfers.Set(fileid, FileRecord{UserId: userid, Path: path},
					ttlcache.DefaultTTL)
			case 2: // XrdXrootdMonFileHdr::isTime
				log.Debug("MonPacket: Received a f-stream time packet")
			case 3: // XrdXrootdMonFileHdr::isXfr
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
				if item != nil {
					record = item.Value()
				}
				record.ReadBytes = readBytes
				record.ReadvBytes = readvBytes
				record.WriteBytes = writeBytes
				transfers.Set(fileid, record, ttlcache.DefaultTTL)

			case 4: // XrdXrootdMonFileHdr::isDisc
				log.Debug("MonPacket: Received a f-stream disconnect packet")
				userId := UserId{Id: fileHdr.UserId}
				sessions.Delete(userId)
			default:
				log.Debug("MonPacket: Received an unhandled file monitoring packet "+
					"of type ", fileHdr.RecType)
			}

			bytesRemain -= uint16(fileHdr.RecSize)
			offset += uint32(fileHdr.RecSize)
		}
	case 'g':
		log.Debug("MonPacket: Received a g-stream packet")
	case 'u':
		log.Debug("MonPacket: Received a user login packet")
		infoSize := uint32(header.Plen - 12)
		if userid, auth, err := GetSIDRest(packet[12 : 12+infoSize]); err == nil {
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
				}
			}
			sessions.Set(userid, record, ttlcache.DefaultTTL)
		} else {
			return err
		}
	default:
		log.Debugf("MonPacket: Received an unhandled monitoring packet of type %v", header.Code)
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
	if err := xml.Unmarshal(packet, &summaryStats); err != nil {
		return err
	}
	log.Debug("Received a summary statistics packet")
	for _, stat := range summaryStats.Stats {
		switch stat.Id {

		case "link":
			incBy := float64(stat.LinkConnections - lastStats.LinkConnections)
			if stat.LinkConnections < lastStats.LinkConnections {
				incBy = float64(stat.LinkConnections)
			}
			Connections.Add(incBy)
			lastStats.LinkConnections = stat.LinkConnections

			incBy = float64(stat.LinkInBytes - lastStats.LinkInBytes)
			if stat.LinkInBytes < lastStats.LinkInBytes {
				incBy = float64(stat.LinkInBytes)
			}
			BytesXfer.With(prometheus.Labels{"direction": "rx"}).Add(incBy)
			lastStats.LinkInBytes = stat.LinkInBytes

			incBy = float64(stat.LinkOutBytes - lastStats.LinkOutBytes)
			if stat.LinkOutBytes < lastStats.LinkOutBytes {
				incBy = float64(stat.LinkOutBytes)
			}
			BytesXfer.With(prometheus.Labels{"direction": "tx"}).Add(incBy)
			lastStats.LinkOutBytes = stat.LinkOutBytes
		case "sched":
			Threads.With(prometheus.Labels{"state": "idle"}).Set(float64(stat.ThreadsIdle))
			Threads.With(prometheus.Labels{"state": "running"}).Set(float64(stat.Threads -
				stat.ThreadsIdle))
		}
	}
	return nil
}
