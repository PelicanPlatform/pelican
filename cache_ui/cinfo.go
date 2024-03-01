package cache_ui

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/pkg/errors"
)

type (
	cInfo struct {
		Store            store
		cksum            uint32
		buffSynced       []byte
		cksumSyncedAstat uint32
	}

	store struct {
		BufferSize   int64
		FileSize     int64
		CreationTime int64 // Unix time in seconds
		NoCkSumTime  int64 // Unix time in seconds
		AccessCnt    uint64
		Status       uint32 // Checksum status
		AStatSize    int32  // Should always be unset (0) unless you know what you are doing
	}
)

const (
	defaultCinfoVersion = 4
)

// SetFCheckSumCheck sets the f_cksum_check value.
// val is expected to fit within 3 bits.
func (st *store) SetFCheckSumCheck(val uint32) {
	const mask uint32 = 0b111 // 3 bits for f_cksum_check
	// Clear the f_cksum_check bits then set to val
	st.Status = (st.Status &^ (mask << 0)) | ((val & mask) << 0)
}

func (st *store) Serialize() ([]byte, error) {
	if st.BufferSize == 0 {
		st.BufferSize = 131072 // 128K, same as pfc.blocksize in xrootd-cache.cfg
	}
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, st.BufferSize)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at BufferSize:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, st.FileSize)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at FileSize:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, st.CreationTime)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at CreationTime:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, st.NoCkSumTime)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at NoCkSumTime:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, st.AccessCnt)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at AccessCnt:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, st.Status)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at Status:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, st.AStatSize)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at AStatSize:", err))
	}
	return buf.Bytes(), nil
}

func (info *cInfo) Serialize() ([]byte, error) {
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, int32(defaultCinfoVersion))
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at DefaultCinfoVersion:", err))
	}
	storeBytes, err := info.Store.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Fail to serialize Store")
	}
	err = binary.Write(&buf, binary.LittleEndian, storeBytes)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at Store:", err))
	}
	info.cksum = crc32.Checksum(storeBytes, crc32c)
	err = binary.Write(&buf, binary.LittleEndian, info.cksum)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at Cksum:", err))
	}
	buffBlockSize := (info.Store.FileSize-1)/info.Store.BufferSize + 1
	if buffBlockSize != 0 {
		buffBlockSize = (buffBlockSize-1)/8 + 1
	}
	info.buffSynced = make([]byte, buffBlockSize)
	// Set all bits in each byte to 1, as this buff block is to record # of blocks
	// read into the cache.
	for i := range info.buffSynced {
		info.buffSynced[i] = 0xff
	}
	err = binary.Write(&buf, binary.LittleEndian, info.buffSynced)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at BufferBlock:", err))
	}
	// AStat is ignored as we don't want to deal with cache access stat for now

	// For checksum, since we ignored AStat, we should only do crc32 on buffSynced
	info.cksumSyncedAstat = crc32.Checksum(info.buffSynced, crc32c)
	err = binary.Write(&buf, binary.LittleEndian, info.cksumSyncedAstat)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at cksumSyncedAstat:", err))
	}
	return buf.Bytes(), nil
}
