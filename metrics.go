package pelican

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
        "github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
        log "github.com/sirupsen/logrus"
        "github.com/spf13/viper"
	"github.com/zsais/go-gin-prometheus"
)

type (
	UserId struct {
		Id uint32
	}

	UserRecord struct {
		AuthenticationProtocol string
		DN string
		Role string
		Org string
	}

	FileId struct {
		Id uint32
	}

	FileRecord struct {
		UserId UserId
		Path string
		ReadOps uint32
		ReadvOps uint32
		WriteOps uint32
		ReadvSegs uint64
		ReadBytes uint64
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
	}, []string{"path", "ap", "dn", "role", "org"})

	TransferBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_bytes",
		Help: "Bytes of transfers",
	}, []string{"path", "ap", "dn", "role", "org"})

	sessions = ttlcache.New[UserId, UserRecord](ttlcache.WithTTL[UserId, UserRecord](24 * time.Hour))
	transfers = ttlcache.New[FileId, FileRecord](ttlcache.WithTTL[FileId, FileRecord](24 * time.Hour))
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

func ConfigureMetrics(engine *gin.Engine) error {
	prometheusMonitor := ginprometheus.NewPrometheus("gin")
	prometheusMonitor.Use(engine)
	/*handler := promhttp.Handler()
	engine.GET("/metrics", func(context *gin.Context) {
		handler.ServeHTTP(context.Writer, context.Request)
	})*/
	return nil
}



func ComputePrefix(inputPath string) string {
	if len(monitorPaths) == 0 {
		return "/"
	}

	segments := strings.Split(path.Clean(inputPath), "/")

	maxlen := 0
	for _, pathList := range(monitorPaths) {
		if len(pathList.Paths) > len(segments) {
			continue
		}
		for idx, segment := range(pathList.Paths) {
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
		return "/";
	}

	result := ""
	for idx := 1; idx < maxlen + 1; idx++ {
		result += "/" + segments[idx];
	}
	return path.Clean(result);
}

func GetSIDRest(info []byte) (UserId, string, error) {
	infoSplit := strings.SplitN(string(info), "\n", 2)
	if len(infoSplit) == 1 {
		return UserId{}, "", errors.New("Unable to parse SID")
	}

	sidInfo := strings.Split(string(info[0]), ":")
	if len(sidInfo) == 1 {
		return UserId{}, "", errors.New("Unable to parse valid SID")
	}
	sid, err := strconv.Atoi(sidInfo[len(sidInfo)-1])
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
		FileId: binary.BigEndian.Uint32(packet[4:8]),
		UserId: binary.BigEndian.Uint32(packet[4:8]),
		NRecs0: int16(binary.BigEndian.Uint16(packet[4:6])),
		NRecs1: int16(binary.BigEndian.Uint16(packet[6:8])),
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
		path := ComputePrefix(rest);
		transfers.Set(fileid, FileRecord{UserId: userid, Path: path}, ttlcache.DefaultTTL)
	case 'f':
		log.Debug("HandlePacket: Received a f-stream packet")
		// sizeof(XrdXrootdMonHeader) + sizeof(XrdXrootdMonFileTOD)
		if len(packet) < 8 + 24 {
			return errors.New("Packet is too small to be a valid f-stream packet")
		}
		firstHeaderSize := binary.BigEndian.Uint16(packet[10:12])
		if firstHeaderSize < 24 {
			return fmt.Errorf("First entry in f-stream packet is %v bytes, smaller than the minimum XrdXrootdMonFileTOD size of 24 bytes")
		}
		offset := uint32(firstHeaderSize + 8)
		bytesRemain := header.Plen - uint16(offset)
		for bytesRemain > 0 {
			fileHdr, err := ParseFileHeader(packet[offset:offset + 8])
			if err != nil {
				return err
			}
			bytesRemain -= uint16(fileHdr.RecSize)

			switch(fileHdr.RecType) {
			case 0: // XrdXrootdMonFileHdr::isClose
				log.Debug("Received a f-stream file-close packet")
				fileId := FileId{Id: fileHdr.FileId}
				xferRecord := transfers.Get(fileId)
				transfers.Delete(fileId)
				labels := prometheus.Labels{}
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
				if fileHdr.RecFlag & 0x02 == 0x02 { // XrdXrootdMonFileHdr::hasOPS
					// sizeof(XrdXrootdMonFileHdr) + sizeof(XrdXrootdMonStatXFR)
					opsOffset := uint32(8 + 24)
					counter := TransferReadvSegs.With(labels)
					counter.Add(float64(int64(binary.BigEndian.Uint64(
						packet[offset + opsOffset + 16:offset + opsOffset + 20]) -
						oldReadvSegs)))
					labels["type"] = "read"
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset + opsOffset:offset + opsOffset + 4]) -
						oldReadOps)))
					labels["type"] = "readv"
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset + opsOffset + 4:offset + opsOffset + 8]) -
						oldReadvOps)))
					labels["type"] = "write"
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset + opsOffset + 8:offset + opsOffset + 12]) -
						oldWriteOps)))
				}
				xfrOffset := uint32(8) // sizeof(XrdXrootdMonFileHdr)
				labels["type"] = "read"
				counter := TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset + xfrOffset:offset + xfrOffset + 8]) -
					oldReadBytes)))
				labels["type"] = "readv"
				counter = TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset + xfrOffset + 8:offset + xfrOffset + 16]) -
					oldReadvBytes)))
				labels["type"] = "write"
				counter = TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset + xfrOffset + 16:offset + xfrOffset + 24]) -
					oldWriteBytes)))
			case 1: // XrdXrootdMonFileHdr::isOpen
				log.Debug("MonPacket: Received a f-stream file-open packet")
				fileid := FileId{Id: fileHdr.FileId}
				path := ""
				if fileHdr.RecFlag & 0x01 == 0x01 { // hasLFN
					lfnSize := uint32(fileHdr.RecSize - 20)
					lfn := NullTermToString(packet[offset + 20:offset + lfnSize + 20])
					path := ComputePrefix(lfn)
					log.Debugf("MonPacket: User LFN %v matches prefix %v",
						lfn, path)
				}
				userid := UserId{Id: binary.BigEndian.Uint32(packet[offset + 16:
					offset + 20])}
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
				readBytes := binary.BigEndian.Uint64(packet[offset + 8:offset + 16])
				readvBytes := binary.BigEndian.Uint64(packet[offset + 16:offset + 24])
				writeBytes := binary.BigEndian.Uint64(packet[offset + 24:offset + 32])
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
				log.Debugf("MonPacket: Received an unhandled file monitoring packet " +
					"of type %v", fileHdr.RecType)
			}

			offset += uint32(fileHdr.RecSize)
		}
	case 'g':
		log.Debug("MonPacket: Received a g-stream packet")
	case 'u':
		log.Debug("MonPacket: Received a user login packet")
		infoSize := uint32(header.Plen - 12)
		if userid, auth, err := GetSIDRest(packet[12:12 + infoSize]); err == nil {
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
			log.Error("Unable to parse user login packet")
		}
	default:
		log.Debug("MonPacket: Received an unhandled monitoring packet of type %v", header.Code)
	}

	return nil

}
