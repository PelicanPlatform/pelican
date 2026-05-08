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

package metrics

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

// TransferEvent describes a completed file transfer from the internal HTTP backend.
// It contains all the information needed to generate XRootD-compatible monitoring packets.
type TransferEvent struct {
	// Path is the logical file name (federation namespace path)
	Path string
	// ReadBytes is the total bytes read from the file (GET/download)
	ReadBytes int64
	// WriteBytes is the total bytes written to the file (PUT/upload)
	WriteBytes int64
	// ReadOps is the number of read operations
	ReadOps int32
	// WriteOps is the number of write operations
	WriteOps int32
	// ClientIP is the client's IP address (possibly masked)
	ClientIP string
	// UserDN is the distinguished name from the token (the "sub" claim or mapped user)
	UserDN string
	// Role is the token role
	Role string
	// AuthProtocol is the authentication protocol (e.g. "ztn" for SciToken, "https" for OIDC)
	AuthProtocol string
	// Issuer is the token issuer URL
	Issuer string
	// Project is the project name from the user agent
	Project string
	// UserAgent is the full User-Agent header value for the 'i' (appinfo) packet
	UserAgent string
	// StartTime is when the transfer started
	StartTime time.Time
	// EndTime is when the transfer ended
	EndTime time.Time
}

// TransferMonitor tracks an in-flight transfer and can emit periodic isXfr
// records as well as a final isClose record. Create one via BeginTransferMonitor.
type TransferMonitor struct {
	fileId uint32
	userId uint32
	ch     chan []byte
	event  TransferEvent
}

var (
	// internalMonitorChan receives internally-generated monitoring packets
	// (base64-encoded JSON messages ready for the shoveler queue).
	// The channel is created lazily on first use.
	internalMonitorChan     chan []byte
	internalMonitorChanOnce sync.Once

	// serverStartTime is used as the Stod field in monitoring packets
	serverStartTime int32

	// nextFileId is a monotonically increasing counter for assigning file IDs
	nextFileId atomic.Uint32

	// nextUserId is a monotonically increasing counter for assigning user IDs
	nextUserId atomic.Uint32

	// pseqCounter is a packet sequence counter for f-stream packets
	pseqCounter atomic.Uint32

	// serverSID is the synthetic server ID used in f-stream TOD records
	serverSID int64
)

func init() {
	serverStartTime = int32(time.Now().Unix())
	// Use a synthetic SID that won't collide with XRootD's SID
	// XRootD uses pid << 56 | time. We use a recognizable but non-colliding value.
	serverSID = int64(0x7E)<<56 | int64(time.Now().Unix()&0x00FFFFFFFFFFFFFF)
}

// GetInternalMonitorChan returns the channel for internally-generated monitoring packets.
// The channel is created once and shared across all producers/consumers.
func GetInternalMonitorChan() chan []byte {
	internalMonitorChanOnce.Do(func() {
		internalMonitorChan = make(chan []byte, 1024)
	})
	return internalMonitorChan
}

// EmitTransferEvent generates XRootD-compatible binary monitoring packets for a completed
// transfer and sends them to the internal monitoring channel for the shoveler.
// This is a convenience wrapper that emits open + close in one shot (no intermediate isXfr).
// For long-running transfers that need periodic reporting, use BeginTransferMonitor instead.
func EmitTransferEvent(event TransferEvent) {
	mon := BeginTransferMonitor(event)
	if mon == nil {
		return
	}
	mon.Close(event.ReadBytes, event.WriteBytes, event.ReadOps, event.WriteOps)
}

// BeginTransferMonitor starts monitoring a transfer. It emits a 'u' (user login)
// packet and an 'f' (f-stream) packet with isOpen, then returns a TransferMonitor
// that can emit periodic isXfr records and a final isClose.
// Returns nil if the shoveler is disabled or if the packets could not be built.
func BeginTransferMonitor(event TransferEvent) *TransferMonitor {
	if !param.Shoveler_Enable.GetBool() {
		return nil
	}

	ch := GetInternalMonitorChan()

	userId := nextUserId.Add(1)
	fileId := nextFileId.Add(1)
	pseq := pseqCounter.Add(1)

	// Build a synthetic XrdUserId for the user login packet
	xrdUserId := XrdUserId{
		Prot: event.AuthProtocol,
		User: event.UserDN,
		Pid:  1,
		Sid:  int(serverSID & 0xFFFFFFFF),
		Host: event.ClientIP,
	}
	if xrdUserId.Prot == "" {
		xrdUserId.Prot = "https"
	}
	if xrdUserId.User == "" {
		xrdUserId.User = "anonymous"
	}
	if xrdUserId.Host == "" {
		xrdUserId.Host = "unknown"
	}

	// 1. Generate 'u' (user login) packet
	userLoginPacket, err := buildUserLoginPacket(byte(pseq), userId, xrdUserId, event)
	if err != nil {
		log.Debugf("Failed to build user login monitoring packet: %v", err)
		return nil
	}
	sendPacketToChannel(ch, userLoginPacket)

	// 2. Generate 'i' (appinfo) packet with user agent
	if event.UserAgent != "" {
		appInfoPacket, err := buildAppInfoPacket(byte(pseqCounter.Add(1)), userId, xrdUserId, event)
		if err != nil {
			log.Debugf("Failed to build appinfo monitoring packet: %v", err)
		} else {
			sendPacketToChannel(ch, appInfoPacket)
		}
	}

	// 3. Generate 'f' (f-stream) packet with isOpen only
	openPacket, err := buildFStreamOpenPacket(byte(pseqCounter.Add(1)), fileId, userId, event)
	if err != nil {
		log.Debugf("Failed to build f-stream open monitoring packet: %v", err)
		return nil
	}
	sendPacketToChannel(ch, openPacket)

	return &TransferMonitor{
		fileId: fileId,
		userId: userId,
		ch:     ch,
		event:  event,
	}
}

// EmitXfr sends a periodic isXfr (intermediate transfer) record with the
// current cumulative byte counts. Call this periodically during long-running
// transfers to provide intermediate visibility.
func (tm *TransferMonitor) EmitXfr(readBytes, writeBytes int64) {
	packet, err := buildFStreamXfrPacket(byte(pseqCounter.Add(1)), tm.fileId, readBytes, writeBytes)
	if err != nil {
		log.Debugf("Failed to build f-stream xfr monitoring packet: %v", err)
		return
	}
	sendPacketToChannel(tm.ch, packet)
}

// Close sends the final isClose record with the total byte counts and
// operation counts, followed by an isDisc (disconnect) record.
// This must be called exactly once when the transfer ends.
func (tm *TransferMonitor) Close(readBytes, writeBytes int64, readOps, writeOps int32) {
	// Emit the isClose record
	packet, err := buildFStreamClosePacket(byte(pseqCounter.Add(1)), tm.fileId, readBytes, writeBytes, readOps, writeOps)
	if err != nil {
		log.Debugf("Failed to build f-stream close monitoring packet: %v", err)
		return
	}
	sendPacketToChannel(tm.ch, packet)

	// Emit the isDisc (disconnect) record to clean up the session
	discPacket, err := buildFStreamDiscPacket(byte(pseqCounter.Add(1)), tm.userId)
	if err != nil {
		log.Debugf("Failed to build f-stream disconnect monitoring packet: %v", err)
		return
	}
	sendPacketToChannel(tm.ch, discPacket)
}

// sendPacketToChannel attempts to send a packet to the internal monitoring channel.
// It drops the packet if the channel is full to avoid blocking the HTTP handler.
func sendPacketToChannel(ch chan []byte, packet []byte) {
	select {
	case ch <- packet:
	default:
		log.Debug("Internal monitoring channel full, dropping packet")
	}
}

// buildUserLoginPacket creates a 'u' (user login) monitoring packet.
// Format:
//
//	XrdXrootdMonHeader (8 bytes): code='u', pseq, plen, stod
//	dictid (4 bytes): user ID
//	info (variable): "prot/user.pid:sid@host\n&p=prot&n=dn&o=org&r=role"
func buildUserLoginPacket(pseq byte, userId uint32, xrdUserId XrdUserId, event TransferEvent) ([]byte, error) {
	// Build the info string
	userIdStr := getUserIdString(xrdUserId)
	authInfo := "&p=" + event.AuthProtocol + "&n=" + event.UserDN + "&o=" + event.Issuer + "&r=" + event.Role
	info := userIdStr + "\n" + authInfo

	infoBytes := []byte(info)
	// Ensure null terminated
	if len(infoBytes) == 0 || infoBytes[len(infoBytes)-1] != 0 {
		infoBytes = append(infoBytes, 0)
	}

	plen := uint16(12 + len(infoBytes))

	monMap := XrdXrootdMonMap{
		Hdr: XrdXrootdMonHeader{
			Code: 'u',
			Pseq: pseq,
			Plen: plen,
			Stod: serverStartTime,
		},
		Dictid: userId,
		Info:   infoBytes,
	}

	return monMap.Serialize()
}

// getUserIdString builds a user ID string in XRootD format: "prot/user.pid:sid@host"
func getUserIdString(u XrdUserId) string {
	return u.Prot + "/" + u.User + "." + strconv.Itoa(u.Pid) + ":" + strconv.Itoa(u.Sid) + "@" + u.Host
}

// buildAppInfoPacket creates an 'i' (appinfo) monitoring packet.
// Format: XrdXrootdMonMap with code='i', dictid=userId.
// Info = "prot/user.pid:sid@host\n<user-agent-string>"
func buildAppInfoPacket(pseq byte, userId uint32, xrdUserId XrdUserId, event TransferEvent) ([]byte, error) {
	userIdStr := getUserIdString(xrdUserId)
	info := userIdStr + "\n" + event.UserAgent

	infoBytes := append([]byte(info), 0)
	plen := uint16(12 + len(infoBytes))

	monMap := XrdXrootdMonMap{
		Hdr: XrdXrootdMonHeader{
			Code: 'i',
			Pseq: pseq,
			Plen: plen,
			Stod: serverStartTime,
		},
		Dictid: userId,
		Info:   infoBytes,
	}

	return monMap.Serialize()
}

// buildFStreamDiscPacket creates an 'f' (f-stream) packet containing only
// an isDisc (disconnect) record. This cleans up the session entry for the user.
func buildFStreamDiscPacket(pseq byte, userId uint32) ([]byte, error) {
	now := int32(time.Now().Unix())

	tod := XrdXrootdMonFileTOD{
		Hdr: XrdXrootdMonFileHdr{
			RecType: isTime,
			RecFlag: 0x01, // hasSID
			RecSize: 24,
			NRecs0:  0, // isXfr records count
			NRecs1:  1, // total records (just disc)
		},
		TBeg: now,
		TEnd: now,
		SID:  serverSID,
	}

	discHdr := XrdXrootdMonFileHdr{
		RecType: isDisc,
		RecFlag: 0,
		RecSize: 8,
		UserId:  userId,
	}

	totalLen := 8 + int(tod.Hdr.RecSize) + int(discHdr.RecSize)
	header := XrdXrootdMonHeader{
		Code: 'f',
		Pseq: pseq,
		Plen: uint16(totalLen),
		Stod: serverStartTime,
	}

	var buf bytes.Buffer
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream header")
	}
	buf.Write(headerBytes)

	todBytes, err := tod.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream TOD")
	}
	buf.Write(todBytes)

	discBytes, err := discHdr.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream disconnect header")
	}
	buf.Write(discBytes)

	return buf.Bytes(), nil
}

// buildFStreamOpenPacket creates an 'f' (f-stream) packet containing only an isOpen record.
func buildFStreamOpenPacket(pseq byte, fileId, userId uint32, event TransferEvent) ([]byte, error) {
	now := int32(time.Now().Unix())
	startTime := int32(event.StartTime.Unix())
	if startTime == 0 {
		startTime = now
	}

	tod := XrdXrootdMonFileTOD{
		Hdr: XrdXrootdMonFileHdr{
			RecType: isTime,
			RecFlag: 0x01, // hasSID
			RecSize: 24,
			NRecs0:  0, // isXfr records count
			NRecs1:  1, // total records (just open)
		},
		TBeg: startTime,
		TEnd: now,
		SID:  serverSID,
	}

	pathBytes := []byte(event.Path)
	pathBytes = append(pathBytes, 0)
	for len(pathBytes)%4 != 0 {
		pathBytes = append(pathBytes, 0)
	}

	opnRecSize := int16(16 + 4 + len(pathBytes)) // header(8) + fsz(8) + userId(4) + lfn
	opnHdr := XrdXrootdMonFileHdr{
		RecType: isOpen,
		RecFlag: 0x01, // hasLFN
		RecSize: opnRecSize,
		FileId:  fileId,
	}

	totalLen := 8 + int(tod.Hdr.RecSize) + int(opnRecSize)
	header := XrdXrootdMonHeader{
		Code: 'f',
		Pseq: pseq,
		Plen: uint16(totalLen),
		Stod: serverStartTime,
	}

	var buf bytes.Buffer
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream header")
	}
	buf.Write(headerBytes)

	todBytes, err := tod.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream TOD")
	}
	buf.Write(todBytes)

	opnHdrBytes, err := opnHdr.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream open header")
	}
	buf.Write(opnHdrBytes)

	if err := binary.Write(&buf, binary.BigEndian, int64(0)); err != nil {
		return nil, errors.Wrap(err, "failed to serialize Fsz")
	}
	if err := binary.Write(&buf, binary.BigEndian, userId); err != nil {
		return nil, errors.Wrap(err, "failed to serialize open UserId")
	}
	buf.Write(pathBytes)

	return buf.Bytes(), nil
}

// buildFStreamXfrPacket creates an 'f' (f-stream) packet containing only an isXfr
// record with cumulative byte counts. Used for periodic intermediate reporting.
func buildFStreamXfrPacket(pseq byte, fileId uint32, readBytes, writeBytes int64) ([]byte, error) {
	now := int32(time.Now().Unix())

	tod := XrdXrootdMonFileTOD{
		Hdr: XrdXrootdMonFileHdr{
			RecType: isTime,
			RecFlag: 0x01, // hasSID
			RecSize: 24,
			NRecs0:  1, // isXfr records count
			NRecs1:  1, // total records (just xfr)
		},
		TBeg: now,
		TEnd: now,
		SID:  serverSID,
	}

	xfrRec := XrdXrootdMonFileXFR{
		Hdr: XrdXrootdMonFileHdr{
			RecType: isXfr,
			RecFlag: 0,
			RecSize: 32, // 8 (hdr) + 24 (xfr)
			FileId:  fileId,
		},
		Xfr: XrdXrootdMonStatXFR{
			Read:  readBytes,
			Readv: 0,
			Write: writeBytes,
		},
	}

	totalLen := 8 + int(tod.Hdr.RecSize) + int(xfrRec.Hdr.RecSize) // header + TOD + XFR
	header := XrdXrootdMonHeader{
		Code: 'f',
		Pseq: pseq,
		Plen: uint16(totalLen),
		Stod: serverStartTime,
	}

	var buf bytes.Buffer
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream header")
	}
	buf.Write(headerBytes)

	todBytes, err := tod.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream TOD")
	}
	buf.Write(todBytes)

	xfrBytes, err := xfrRec.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream xfr")
	}
	buf.Write(xfrBytes)

	return buf.Bytes(), nil
}

// buildFStreamClosePacket creates an 'f' (f-stream) packet containing only an isClose record.
func buildFStreamClosePacket(pseq byte, fileId uint32, readBytes, writeBytes int64, readOps, writeOps int32) ([]byte, error) {
	now := int32(time.Now().Unix())

	tod := XrdXrootdMonFileTOD{
		Hdr: XrdXrootdMonFileHdr{
			RecType: isTime,
			RecFlag: 0x01, // hasSID
			RecSize: 24,
			NRecs0:  0, // isXfr records count
			NRecs1:  1, // total records (just close)
		},
		TBeg: now,
		TEnd: now,
		SID:  serverSID,
	}

	cls := XrdXrootdMonFileCLS{
		Hdr: XrdXrootdMonFileHdr{
			RecType: isClose,
			RecFlag: 0x02, // hasOPS
			RecSize: 80,   // 8 (hdr) + 24 (xfr) + 48 (ops)
			FileId:  fileId,
		},
		Xfr: XrdXrootdMonStatXFR{
			Read:  readBytes,
			Readv: 0,
			Write: writeBytes,
		},
		Ops: XrdXrootdMonStatOPS{
			Read:  readOps,
			Readv: 0,
			Write: writeOps,
		},
	}

	totalLen := 8 + int(tod.Hdr.RecSize) + int(cls.Hdr.RecSize)
	header := XrdXrootdMonHeader{
		Code: 'f',
		Pseq: pseq,
		Plen: uint16(totalLen),
		Stod: serverStartTime,
	}

	var buf bytes.Buffer
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream header")
	}
	buf.Write(headerBytes)

	todBytes, err := tod.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream TOD")
	}
	buf.Write(todBytes)

	clsBytes, err := cls.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize f-stream close")
	}
	buf.Write(clsBytes)

	return buf.Bytes(), nil
}
