package cache_ui

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/pkg/errors"
)

type (
	CInfo struct {
		Store            Store
		cksum            uint32
		buffSynced       []byte
		cksumSyncedAstat uint32
	}

	Store struct {
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
	DefaultCinfoVersion = 4
)

// SetFCheckSumCheck sets the f_cksum_check value.
// val is expected to fit within 3 bits.
func (store *Store) SetFCheckSumCheck(val uint32) {
	const mask uint32 = 0b111 // 3 bits for f_cksum_check
	// Clear the f_cksum_check bits then set to val
	store.Status = (store.Status &^ (mask << 0)) | ((val & mask) << 0)
}

func (store *Store) Serialize() ([]byte, error) {
	if store.BufferSize == 0 {
		store.BufferSize = 131072 // 128K, same as pfc.blocksize in xrootd-cache.cfg
	}
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, store.BufferSize)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at BufferSize:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, store.FileSize)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at FileSize:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, store.CreationTime)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at CreationTime:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, store.NoCkSumTime)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at NoCkSumTime:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, store.AccessCnt)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at AccessCnt:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, store.Status)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at Status:", err))
	}
	err = binary.Write(&buf, binary.LittleEndian, store.AStatSize)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at AStatSize:", err))
	}
	return buf.Bytes(), nil
}

func (cinfo *CInfo) Serialize() ([]byte, error) {
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, int32(DefaultCinfoVersion))
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at DefaultCinfoVersion:", err))
	}
	storeBytes, err := cinfo.Store.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "Fail to serialize Store")
	}
	err = binary.Write(&buf, binary.LittleEndian, storeBytes)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at Store:", err))
	}
	cinfo.cksum = crc32.Checksum(storeBytes, crc32c)
	err = binary.Write(&buf, binary.LittleEndian, cinfo.cksum)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at Cksum:", err))
	}
	buffBlockSize := (cinfo.Store.FileSize-1)/cinfo.Store.BufferSize + 1
	if buffBlockSize != 0 {
		buffBlockSize = (buffBlockSize-1)/8 + 1
	}
	cinfo.buffSynced = make([]byte, buffBlockSize)
	// Set all bits in each byte to 1, as this buff block is to record # of blocks
	// read into the cache.
	for i := range cinfo.buffSynced {
		cinfo.buffSynced[i] = 0xff
	}
	err = binary.Write(&buf, binary.LittleEndian, cinfo.buffSynced)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at BufferBlock:", err))
	}
	// AStat is ignored as we don't want to deal with cache access stat for now

	// For checksum, since we ignored AStat, we should only do crc32 on buffSynced
	cinfo.cksumSyncedAstat = crc32.Checksum(cinfo.buffSynced, crc32c)
	err = binary.Write(&buf, binary.LittleEndian, cinfo.cksumSyncedAstat)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Fail to serialize CInfo at cksumSyncedAstat:", err))
	}
	return buf.Bytes(), nil
}
