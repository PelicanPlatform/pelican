// +build windows

package stashcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

//   Given a local filename, create a unique identifier from filesystem
//   metadata; anytime the file contents change, the unique identifier
//   should also change.  The hash changes once every 24 hours to allow
//   the shadow origin to do garbage collection.
//
//   The current algorithm to generate the unique identifier is to
//   take the concatenation of the following byte buffers:
//
//   - basename of the path.
//   - mtime # as a double string
//   - Current unix epoch time, as integer, divided by 86400
//
//   and then running it through a SHA256 sum to produce a digest.
//
//   The hex digest of the SHA256 sum is returned
func unique_hash(filePath string) (string, error) {
	log.Debugf("Creating a unique hash for filename %s", filePath)

	st, err := os.Stat(filePath)
	if err != nil {
		log.Debugln("Error while stat'ing file for metadata:", err)
		return "", err;
	}

	digest := sha256.New()
	digest.Write([]byte(filePath))
	digest.Write([]byte(st.ModTime().Format(time.RFC3339Nano)))

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, time.Now().Unix()/86400); err != nil {
		log.Debugln("Error while writing current Unix time to buffer:", err)
		return "", err;
	}
	digest.Write(buf.Bytes())

	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}
