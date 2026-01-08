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

package client

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

// bytesWriter wraps a byte slice to implement io.Writer
type bytesWriter struct {
	buf []byte
	n   int
}

func (w *bytesWriter) Write(p []byte) (n int, err error) {
	n = copy(w.buf[w.n:], p)
	w.n += n
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// PelicanFS implements io.FS for the Pelican data federation.
// It provides a filesystem-like interface to objects stored in the federation.
type PelicanFS struct {
	ctx     context.Context
	options []TransferOption
}

// NewPelicanFS creates a new filesystem interface to the Pelican federation.
// The provided context is used for all operations, and the options are applied
// to all transfers.
func NewPelicanFS(ctx context.Context, options ...TransferOption) *PelicanFS {
	return &PelicanFS{
		ctx:     ctx,
		options: options,
	}
}

// Open opens the named file for reading and returns a fs.File that also
// implements io.ReaderAt and io.Seeker.
func (pfs *PelicanFS) Open(name string) (fs.File, error) {
	// Validate the name
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	// Stat the file to get its metadata
	statInfo, err := DoStat(pfs.ctx, name, pfs.options...)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	// Create and return a PelicanFile
	pf := &PelicanFile{
		ctx:      pfs.ctx,
		name:     name,
		fileInfo: statInfo,
		options:  pfs.options,
		position: 0,
	}

	return pf, nil
}

// PelicanFile represents an open file in the Pelican federation.
// It implements fs.File, io.ReaderAt, and io.Seeker.
type PelicanFile struct {
	ctx      context.Context
	name     string
	fileInfo *FileInfo
	options  []TransferOption
	position int64
	closed   bool
	mu       sync.Mutex

	// For full-file reads using TransferEngine
	transferStarted bool
	readPipe        io.ReadCloser
	writePipe       io.WriteCloser
	transferErr     error
	transferDone    chan struct{}
}

// Read reads up to len(p) bytes into p. It returns the number of bytes read (0 <= n <= len(p))
// and any error encountered. For a full file read (no prior Seek or ReadAt),
// this uses the TransferEngine for optimized downloads.
func (pf *PelicanFile) Read(p []byte) (n int, err error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return 0, fs.ErrClosed
	}

	// If this is a collection/directory, return an error
	if pf.fileInfo.IsCollection {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("is a directory")}
	}

	// For the first read at position 0, start a transfer using the TransferEngine
	if !pf.transferStarted && pf.position == 0 {
		return pf.startTransferRead(p)
	}

	// If we have an active transfer pipe, read from it
	if pf.readPipe != nil {
		n, err = pf.readPipe.Read(p)
		pf.position += int64(n)
		return n, err
	}

	// Otherwise, use HTTP range requests for partial reads
	return pf.rangeRead(p, pf.position)
}

// startTransferRead initiates a full file transfer using the TransferEngine
func (pf *PelicanFile) startTransferRead(p []byte) (int, error) {
	// Create a pipe for the transfer
	pr, pw := io.Pipe()
	pf.readPipe = pr
	pf.writePipe = pw
	pf.transferDone = make(chan struct{})
	pf.transferStarted = true

	// Start the transfer in a goroutine
	go func() {
		defer close(pf.transferDone)
		defer pw.Close()

		// Use a temporary file for the transfer, then copy to the pipe
		// This is simpler than modifying the entire transfer engine
		tempDir := os.TempDir()
		tempFile, err := os.CreateTemp(tempDir, "pelican-fs-*")
		if err != nil {
			pf.transferErr = err
			pw.CloseWithError(err)
			return
		}
		tempPath := tempFile.Name()
		tempFile.Close()
		defer os.Remove(tempPath)

		// Perform the transfer
		_, err = DoGet(pf.ctx, pf.name, tempPath, false, pf.options...)
		if err != nil {
			pf.transferErr = err
			pw.CloseWithError(err)
			return
		}

		// Open and copy the file to the pipe
		tempFile, err = os.Open(tempPath)
		if err != nil {
			pf.transferErr = err
			pw.CloseWithError(err)
			return
		}
		defer tempFile.Close()

		_, err = io.Copy(pw, tempFile)
		if err != nil {
			pf.transferErr = err
			pw.CloseWithError(err)
			return
		}
	}()

	// Read the first chunk
	n, err := pf.readPipe.Read(p)
	pf.position += int64(n)
	return n, err
}

// rangeRead performs a partial read using HTTP range requests and updates position
func (pf *PelicanFile) rangeRead(p []byte, offset int64) (int, error) {
	if offset >= pf.fileInfo.Size {
		return 0, io.EOF
	}

	// Calculate the range to read
	length := int64(len(p))
	if offset+length > pf.fileInfo.Size {
		length = pf.fileInfo.Size - offset
	}

	// Use doRangeRead to fetch the data directly
	n, err := pf.doRangeRead(p, offset)
	if err != nil {
		return n, err
	}

	pf.position += int64(n)
	return n, nil
}

// doRangeRead performs the actual HTTP range request without updating position
func (pf *PelicanFile) doRangeRead(p []byte, offset int64) (int, error) {
	// Calculate the range to read
	length := int64(len(p))
	if offset+length > pf.fileInfo.Size {
		length = pf.fileInfo.Size - offset
	}

	// Get director information for the path
	pUrl, err := ParseRemoteAsPUrl(pf.ctx, pf.name)
	if err != nil {
		return 0, errors.Wrap(err, "failed to parse remote path")
	}

	dirResp, err := GetDirectorInfoForPath(pf.ctx, pUrl, http.MethodGet, "")
	if err != nil {
		return 0, errors.Wrap(err, "failed to get director info")
	}

	// Get a token if needed
	var tokenContents string
	if dirResp.XPelNsHdr.RequireToken {
		token := NewTokenGenerator(pUrl, &dirResp, config.TokenSharedRead, true)
		for _, option := range pf.options {
			switch option.Ident() {
			case identTransferOptionTokenLocation{}:
				token.SetTokenLocation(option.Value().(string))
			case identTransferOptionAcquireToken{}:
				token.EnableAcquire = option.Value().(bool)
			case identTransferOptionToken{}:
				token.SetToken(option.Value().(string))
			}
		}
		tokenContents, err = token.Get()
		if err != nil || tokenContents == "" {
			return 0, errors.Wrap(err, "failed to get token for range request")
		}
	}

	// Select the first available object server
	if len(dirResp.ObjectServers) == 0 {
		return 0, errors.New("no object servers available")
	}

	// Try each object server until one succeeds
	var lastErr error
	for _, objServer := range dirResp.ObjectServers {
		transferUrl := *objServer
		transferUrl.Path = pUrl.Path

		// Create HTTP request with range header
		req, err := http.NewRequestWithContext(pf.ctx, http.MethodGet, transferUrl.String(), nil)
		if err != nil {
			lastErr = err
			continue
		}

		// Set range header
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))

		// Set authorization if needed
		if tokenContents != "" {
			req.Header.Set("Authorization", "Bearer "+tokenContents)
		}

		// Set user agent
		req.Header.Set("User-Agent", getUserAgent(""))

		// Execute the request
		client := config.GetClient()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		// Check status code (should be 206 Partial Content)
		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			lastErr = errors.Errorf("unexpected status code: %d", resp.StatusCode)
			continue
		}

		// Read the response body into the buffer
		// Use io.Copy with LimitReader for safer partial content handling
		limitedReader := io.LimitReader(resp.Body, length)
		bw := &bytesWriter{buf: p}
		n, err := io.Copy(bw, limitedReader)
		if err != nil {
			lastErr = err
			continue
		}

		return int(n), nil
	}

	if lastErr != nil {
		return 0, errors.Wrap(lastErr, "failed to download range from all object servers")
	}

	return 0, errors.New("no object servers available")
}

// ReadAt reads len(p) bytes into p starting at offset off in the file.
// It implements io.ReaderAt. Note: ReadAt does not affect the file position.
func (pf *PelicanFile) ReadAt(p []byte, off int64) (n int, err error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return 0, fs.ErrClosed
	}

	if pf.fileInfo.IsCollection {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("is a directory")}
	}

	if off < 0 {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("negative offset")}
	}

	if off >= pf.fileInfo.Size {
		return 0, io.EOF
	}

	// Use HTTP range request - don't update position as per io.ReaderAt contract
	return pf.doRangeRead(p, off)
}

// Seek sets the offset for the next Read operation and returns the new offset.
// It implements io.Seeker.
func (pf *PelicanFile) Seek(offset int64, whence int) (int64, error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return 0, fs.ErrClosed
	}

	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = pf.position + offset
	case io.SeekEnd:
		newPos = pf.fileInfo.Size + offset
	default:
		return 0, &fs.PathError{Op: "seek", Path: pf.name, Err: errors.New("invalid whence")}
	}

	if newPos < 0 {
		return 0, &fs.PathError{Op: "seek", Path: pf.name, Err: errors.New("negative position")}
	}

	// If we have an active transfer and we're seeking, close the pipe
	// Future reads will use range requests
	if pf.readPipe != nil && newPos != pf.position {
		pf.readPipe.Close()
		pf.readPipe = nil
	}

	pf.position = newPos
	return pf.position, nil
}

// Stat returns the FileInfo structure describing the file.
// It implements fs.File.
func (pf *PelicanFile) Stat() (fs.FileInfo, error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return nil, fs.ErrClosed
	}

	// Extract just the basename for the name
	name := filepath.Base(pf.name)

	return &pelicanFileInfo{
		name:    name,
		size:    pf.fileInfo.Size,
		modTime: pf.fileInfo.ModTime,
		isDir:   pf.fileInfo.IsCollection,
	}, nil
}

// Close closes the file, rendering it unusable for I/O.
// It implements fs.File.
func (pf *PelicanFile) Close() error {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return nil
	}

	pf.closed = true

	// Close the read pipe if it's open
	if pf.readPipe != nil {
		pf.readPipe.Close()
		pf.readPipe = nil
	}

	// Close the write pipe if it's open
	if pf.writePipe != nil {
		pf.writePipe.Close()
		pf.writePipe = nil
	}

	// Wait for transfer to complete if it was started
	if pf.transferDone != nil {
		<-pf.transferDone
	}

	return pf.transferErr
}

// pelicanFileInfo implements fs.FileInfo for Pelican files
type pelicanFileInfo struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
}

func (pfi *pelicanFileInfo) Name() string       { return pfi.name }
func (pfi *pelicanFileInfo) Size() int64        { return pfi.size }
func (pfi *pelicanFileInfo) Mode() fs.FileMode  { return 0444 } // Read-only
func (pfi *pelicanFileInfo) ModTime() time.Time { return pfi.modTime }
func (pfi *pelicanFileInfo) IsDir() bool        { return pfi.isDir }
func (pfi *pelicanFileInfo) Sys() interface{}   { return nil }
