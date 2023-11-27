/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"fmt"

	"github.com/pkg/errors"
)

func (monHeader *XrdXrootdMonHeader) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	// Writing the Header
	err := binary.Write(&buf, binary.BigEndian, monHeader.Code)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Code:", err))
	}
	err = binary.Write(&buf, binary.BigEndian, monHeader.Pseq)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Pseq:", err))
	}
	err = binary.Write(&buf, binary.BigEndian, monHeader.Plen)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Plen:", err))
	}
	err = binary.Write(&buf, binary.BigEndian, monHeader.Stod)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Stod:", err))
	}

	return buf.Bytes(), nil
}

func (monMap XrdXrootdMonMap) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Writing the Header
	headerBytes, err := monMap.Hdr.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("Failed to serialize monitor header:", err))
	}
	err = binary.Write(&buf, binary.BigEndian, headerBytes)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprint("binary.Write failed for Header:", err))
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

func (hdr *XrdXrootdMonFileHdr) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Serialize RecType
	buf.WriteByte(byte(hdr.RecType))
	// Serialize RecFlag
	buf.WriteByte(hdr.RecFlag)
	// Serialize RecSize
	if err := binary.Write(buf, binary.BigEndian, hdr.RecSize); err != nil {
		return nil, err
	}

	// Serialize the union field based on RecType
	switch hdr.RecType {
	case isTime:
		// Serialize NRecs0 and NRecs1
		if err := binary.Write(buf, binary.BigEndian, hdr.NRecs0); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, hdr.NRecs1); err != nil {
			return nil, err
		}
	case isDisc:
		// Serialize UserID
		if err := binary.Write(buf, binary.BigEndian, hdr.UserId); err != nil {
			return nil, err
		}
	default:
		// Serialize FileID for all other cases (isClose, isOpen, isXFR)
		if err := binary.Write(buf, binary.BigEndian, hdr.FileId); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (ftod *XrdXrootdMonFileTOD) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// First serialize the header
	headerBytes, err := ftod.Hdr.Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(headerBytes)

	// Serialize TBeg
	if err := binary.Write(buf, binary.BigEndian, ftod.TBeg); err != nil {
		return nil, err
	}
	// Serialize TEnd
	if err := binary.Write(buf, binary.BigEndian, ftod.TEnd); err != nil {
		return nil, err
	}
	// Serialize SID
	if err := binary.Write(buf, binary.BigEndian, ftod.SID); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (lfn *XrdXrootdMonFileLFN) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Serialize User
	if err := binary.Write(buf, binary.BigEndian, lfn.User); err != nil {
		return nil, err
	}
	// Serialize Lfn
	// Here we don't need to handle endianness since it's a byte array
	buf.Write(lfn.Lfn[:])

	return buf.Bytes(), nil
}

func (opn *XrdXrootdMonFileOPN) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Serialize the header
	headerBytes, err := opn.Hdr.Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(headerBytes)

	// Serialize Fsz
	if err := binary.Write(buf, binary.BigEndian, opn.Fsz); err != nil {
		return nil, err
	}

	// Serialize Ufn
	lfnBytes, err := opn.Ufn.Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(lfnBytes)

	return buf.Bytes(), nil
}

func (xfr *XrdXrootdMonStatXFR) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Serialize Read
	if err := binary.Write(buf, binary.BigEndian, xfr.Read); err != nil {
		return nil, err
	}
	// Serialize Readv
	if err := binary.Write(buf, binary.BigEndian, xfr.Readv); err != nil {
		return nil, err
	}
	// Serialize Write
	if err := binary.Write(buf, binary.BigEndian, xfr.Write); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (fileXFR *XrdXrootdMonFileXFR) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Serialize the header
	headerBytes, err := fileXFR.Hdr.Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(headerBytes)

	// Serialize the Xfr stats
	xfrBytes, err := fileXFR.Xfr.Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(xfrBytes)

	return buf.Bytes(), nil
}

func (ops *XrdXrootdMonStatOPS) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Serialize each field using binary.Write which encodes according to the specified endianness
	if err := binary.Write(buf, binary.BigEndian, ops.Read); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.Readv); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.Write); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.RsMin); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.RsMax); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.Rsegs); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.RdMin); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.RdMax); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.RvMin); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.RvMax); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.WrMin); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, ops.WrMax); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Serialize converts XrdXrootdMonFileCLS to a byte array
func (cls *XrdXrootdMonFileCLS) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Serialize the header
	headerBytes, err := cls.Hdr.Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(headerBytes)

	// Serialize the Xfr stats
	xfrBytes, err := cls.Xfr.Serialize()
	if err != nil {
		return nil, err
	}
	buf.Write(xfrBytes)

	// Conditionally serialize Ops if hasOPS flag is set
	if cls.Hdr.RecFlag&0x02 == 0x02 {
		opsBytes, err := cls.Ops.Serialize()
		if err != nil {
			return nil, err
		}
		buf.Write(opsBytes)
	}

	// Note: Ssq field is not implemented and thus not serialized

	return buf.Bytes(), nil
}
