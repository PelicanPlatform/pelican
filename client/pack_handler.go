/***************************************************************
 *
 * Copyright (C) 2023, Morgridge Institute for Research
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

package client

import (
	"archive/tar"
	"sync/atomic"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type packerBehavior int

type packedError struct{Value error}

type autoUnpacker struct {
	Behavior     packerBehavior
	detectedType packerBehavior
	destDir      string
	buffer       bytes.Buffer
	writer       io.WriteCloser
	err          atomic.Value
}

const (
	autoBehavior packerBehavior = iota
	tarBehavior
	tarGZBehavior
	tarXZBehavior
	zipBehavior
)

func newAutoUnpacker(destdir string, behavior packerBehavior) *autoUnpacker {
	aup := &autoUnpacker{
		Behavior: behavior,
		destDir: destdir,
	}
	aup.err.Store(packedError{})
	return aup
}

func (aup *autoUnpacker) Error() error {
	value := aup.err.Load()
	if err, ok := value.(packedError); ok {
		return err.Value
	}
	return nil
}

func (aup *autoUnpacker) StoreError(err error) {
	aup.err.CompareAndSwap(packedError{}, packedError{Value: err})
}

func (aup *autoUnpacker) detect() (packerBehavior, error) {
	currentBytes := aup.buffer.Bytes()
	// gzip streams start with 1F 8B
	if len(currentBytes) >= 2 && bytes.Equal(currentBytes[0:2], []byte{0x1F, 0x8B}) {
		return tarGZBehavior, nil
	}
	// xz streams start with FD 37 7A 58 5A 00
	if len(currentBytes) >= 6 && bytes.Equal(currentBytes[0:6], []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}) {
		return tarXZBehavior, nil
	}
	// tar files, at offset 257, have bytes 75 73 74 61 72
	if len(currentBytes) >= (257 + 5) && bytes.Equal(currentBytes[257:257 + 5], []byte{0x75, 0x73, 0x74, 0x61, 0x72}) {
		return tarBehavior, nil
	}
	// zip files start with 50 4B 03 04
	if len(currentBytes) >= 4 && bytes.Equal(currentBytes[0:4], []byte{0x50, 0x4B, 0x03, 0x04}) {
		return zipBehavior, nil
	}
	if len(currentBytes) > (257 + 5) {
		return autoBehavior, errors.New("Unable to detect pack type")
	}
	return autoBehavior, nil
}

func writeRegFile(path string, mode int64, reader io.Reader) error {
	fp, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, fs.FileMode(mode))
	if err != nil {
		return err
	}
	defer fp.Close()
	_, err = io.Copy(fp, reader)
	return err
}

func (aup *autoUnpacker) unpack(tr *tar.Reader, preader *io.PipeReader) {
	log.Debugln("Beginning unpacker of type", aup.Behavior)
	defer preader.Close()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			preader.CloseWithError(err)
			break
		}
		if err != nil {
			aup.StoreError(err)
			break
		}
		destPath := filepath.Join(aup.destDir, hdr.Name)
		destPath = filepath.Clean(destPath)
		if !strings.HasPrefix(destPath, aup.destDir) {
			aup.StoreError(errors.New("Tarfile contains object outside the destination directory"))
			break
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			err = writeRegFile(destPath, hdr.Mode, tr)
			if err != nil {
				aup.StoreError(errors.Wrapf(err, "Failure when unpacking file to %v", destPath))
				return
			}
		case tar.TypeLink:
			targetPath := filepath.Join(aup.destDir, hdr.Linkname)
			if !strings.HasPrefix(targetPath, aup.destDir) {
				aup.StoreError(errors.New("Tarfile contains hard link target outside the destination directory"))
				return
			}
			if err = os.Link(targetPath, destPath); err != nil {
				aup.StoreError(errors.Wrapf(err, "Failure when unpacking hard link to %v", destPath))
				return
			}
		case tar.TypeSymlink:
			if err = os.Symlink(hdr.Linkname, destPath); err != nil {
				aup.StoreError(errors.Wrapf(err, "Failure when creating symlink at %v", destPath))
				return
			}
		case tar.TypeChar:
			continue
			log.Debugln("Ignoring tar entry of type character device at", destPath)
		case tar.TypeBlock:
			continue
			log.Debugln("Ignoring tar entry of type block device at", destPath)
		case tar.TypeDir:
			if err = os.MkdirAll(destPath, fs.FileMode(hdr.Mode)); err != nil {
				aup.StoreError(errors.Wrapf(err, "Failure when creating directory at %v", destPath))
				return
			}
		case tar.TypeFifo:
			continue
			log.Debugln("Ignoring tar entry of type FIFO at", destPath)
		case 103: // pax_global_header, written by git archive.  OK to ignore
			continue
		default:
			log.Debugln("Ignoring unknown tar entry of type", hdr.Typeflag)
		}
	}
}

func (aup *autoUnpacker) configure() (err error) {
	preader, pwriter := io.Pipe()
	bufDrained := make(chan int)
	// gzip.NewReader function will block reading from the pipe.
	// Asynchronously write the contents of the buffer from a separate goroutine;
	// Note we don't return from configure() until the buffer is consumed.
	go func() {
		aup.buffer.WriteTo(pwriter)
		bufDrained<-1
	}()
	var tarUnpacker *tar.Reader
	switch aup.detectedType {
	case autoBehavior:
		return errors.New("Configure invoked before file type is known")
	case tarBehavior:
		tarUnpacker = tar.NewReader(preader)
	case tarGZBehavior:
		gzStreamer, err := gzip.NewReader(preader)
		if err != nil {
			return err
		}
		tarUnpacker = tar.NewReader(gzStreamer)
	case tarXZBehavior:
		return errors.New("tar.xz has not yet been implemented")
	case zipBehavior:
		return errors.New("zip file support has not yet been implemented")
	}
	go aup.unpack(tarUnpacker, preader)
	<-bufDrained
	aup.writer = pwriter
	return nil
}

func (aup *autoUnpacker) Write(p []byte) (n int, err error) {
	if aup.destDir == "" {
		err = errors.New("AutoUnpacker object must be initialized via NewAutoUnpacker")
		return
	}
	err = aup.Error()
	if err != nil {
		if aup.writer != nil {
			aup.writer.Close()
		}
		return
	}

	if aup.detectedType == autoBehavior {
		if n, err = aup.buffer.Write(p); err != nil {
			return
		}
		if aup.detectedType, err = aup.detect(); aup.detectedType == autoBehavior {
			n = len(p)
			return
		} else if err = aup.configure(); err != nil {
			return
		}
		// Note the byte buffer already consumed all the bytes, hence return here.
		return len(p), nil
	} else if aup.writer == nil {
		if err = aup.configure(); err != nil {
			return
		}
	}
	n, writerErr := aup.writer.Write(p)
	if err = aup.Error(); err != nil {
		return n, err
	} else if writerErr != nil {
		if writerErr == io.EOF {
			return len(p), nil
		}
	}
	return n, writerErr
}

func (aup autoUnpacker) Close() {
	if aup.buffer.Len() > 0 {
		aup.StoreError(errors.New("AutoUnpacker was closed prior to detecting any file type; no bytes were written"))
	}
	if aup.Behavior == autoBehavior {
		aup.StoreError(errors.New("AutoUnpacker was closed prior to any bytes written"))
	}
}
