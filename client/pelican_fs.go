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
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

// PelicanFS implements io.FS for the Pelican data federation.
// It provides a filesystem-like interface to objects stored in the federation.
type PelicanFS struct {
	ctx       context.Context
	urlPrefix string // URL prefix for all paths (e.g., "osdf:///")
	options   []TransferOption
}

// NewPelicanFS creates a new filesystem interface to the Pelican federation.
// The provided context is used for all operations, and the options are applied
// to all transfers. If urlPrefix is empty or "/", it defaults to "osdf:///".
func NewPelicanFS(ctx context.Context, options ...TransferOption) *PelicanFS {
	return NewPelicanFSWithPrefix(ctx, "", options...)
}

// NewPelicanFSWithPrefix creates a new filesystem interface with a URL prefix.
// All paths will be relative to this prefix. If prefix is empty or "/", defaults to "osdf:///".
func NewPelicanFSWithPrefix(ctx context.Context, urlPrefix string, options ...TransferOption) *PelicanFS {
	if urlPrefix == "" || urlPrefix == "/" {
		urlPrefix = "osdf:///"
	}
	return &PelicanFS{
		ctx:       ctx,
		urlPrefix: urlPrefix,
		options:   options,
	}
}

// Open opens the named file for reading and returns a fs.File that also
// implements io.ReaderAt, io.Seeker, io.Writer (for write mode), and
// fs.ReadDirFile (for directories).
func (pfs *PelicanFS) Open(name string) (fs.File, error) {
	return pfs.OpenFile(name, os.O_RDONLY)
}

// OpenFile opens the named file with specified flags.
// Supported flags: os.O_RDONLY, os.O_WRONLY, os.O_RDWR, os.O_CREATE
func (pfs *PelicanFS) OpenFile(name string, flag int) (fs.File, error) {
	// Validate the name
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	// Prepend URL prefix to the name
	fullPath := name
	if pfs.urlPrefix != "" && pfs.urlPrefix != "/" {
		fullPath = pfs.urlPrefix + name
	}

	// Parse the URL
	pUrl, err := ParseRemoteAsPUrl(pfs.ctx, fullPath)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	// Determine the operation type based on flags
	writeMode := (flag&os.O_WRONLY) != 0 || (flag&os.O_RDWR) != 0
	readMode := (flag&os.O_RDONLY) != 0 || (flag&os.O_RDWR) != 0
	rdwrMode := (flag & os.O_RDWR) != 0
	
	// Get director info and token generator
	httpMethod := http.MethodGet
	operation := config.TokenSharedRead
	if writeMode && !rdwrMode {
		httpMethod = http.MethodPut
		operation = config.TokenSharedWrite
	}

	dirResp, err := GetDirectorInfoForPath(pfs.ctx, pUrl, httpMethod, "")
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	token := NewTokenGenerator(pUrl, &dirResp, operation, true)
	for _, option := range pfs.options {
		switch option.Ident() {
		case identTransferOptionTokenLocation{}:
			token.SetTokenLocation(option.Value().(string))
		case identTransferOptionAcquireToken{}:
			token.EnableAcquire = option.Value().(bool)
		case identTransferOptionToken{}:
			token.SetToken(option.Value().(string))
		}
	}

	// Get token if required
	var tokenContents string
	if dirResp.XPelNsHdr.RequireToken || writeMode {
		tokenContents, err = token.Get()
		if err != nil || tokenContents == "" {
			return nil, &fs.PathError{Op: "open", Path: name, Err: errors.Wrap(err, "failed to get token")}
		}
	}

	// Stat the file for reads (writes may create new file)
	// For O_RDWR, try to stat first. If file doesn't exist, switch to write-only mode.
	var fileInfo *FileInfo
	if readMode {
		fi, err := statHttp(pUrl, dirResp, token)
		if err != nil {
			if rdwrMode {
				// File doesn't exist in RDWR mode - switch to write-only
				readMode = false
				writeMode = true
				// Update director info and token for PUT
				dirResp, err = GetDirectorInfoForPath(pfs.ctx, pUrl, http.MethodPut, "")
				if err != nil {
					return nil, &fs.PathError{Op: "open", Path: name, Err: err}
				}
				token = NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, true)
				for _, option := range pfs.options {
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
					return nil, &fs.PathError{Op: "open", Path: name, Err: errors.Wrap(err, "failed to get token")}
				}
			} else {
				return nil, &fs.PathError{Op: "open", Path: name, Err: err}
			}
		} else {
			fileInfo = &fi
		}
	}

	// Create transfer engine
	te, err := NewTransferEngine(pfs.ctx)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	tc, err := te.NewClient(pfs.options...)
	if err != nil {
		te.Shutdown()
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	// Create and return a PelicanFile
	pf := &PelicanFile{
		ctx:             pfs.ctx,
		name:            name,
		pUrl:            pUrl,
		fileInfo:        fileInfo,
		options:         pfs.options,
		position:        0,
		transferEngine:  te,
		transferClient:  tc,
		dirResp:         dirResp,
		token:           token,
		tokenContents:   tokenContents,
		readMode:        readMode,
		writeMode:       writeMode,
		rdwrMutex:       flag&os.O_RDWR != 0,
	}

	return pf, nil
}

// PelicanFile represents an open file in the Pelican federation.
// It implements fs.File, io.ReaderAt, io.Seeker, io.Writer, and fs.ReadDirFile.
type PelicanFile struct {
	ctx             context.Context
	name            string
	pUrl            *pelican_url.PelicanURL
	fileInfo        *FileInfo
	options         []TransferOption
	
	// Transfer infrastructure
	transferEngine *TransferEngine
	transferClient *TransferClient
	dirResp        server_structs.DirectorResponse
	token          *tokenGenerator
	tokenContents  string
	currentEndpoint atomic.Int32  // Sticky endpoint index (atomic for lock-free access)
	
	// Position tracking
	position       int64  // Current position in file
	transferOffset int64  // Offset in the active transfer stream
	
	// Transfer state
	transferStarted bool
	transferJob     *TransferJob
	readPipe        io.ReadCloser
	writePipe       io.WriteCloser
	transferErr     error
	transferDone    chan struct{}
	transferResults []TransferResults  // Results from transfer client shutdown
	
	// ReadDir state (for pagination)
	dirEntries     []fs.DirEntry
	dirEntriesRead int  // Number of entries already returned by ReadDir
	
	// Mode flags
	readMode       bool
	writeMode      bool
	rdwrMutex      bool  // If true, forbid reads after writes and vice versa
	hasRead        bool  // Track if any reads occurred
	hasWritten     bool  // Track if any writes occurred
	writePosition  int64 // Track write position for linear write enforcement
	
	closed bool
	mu     sync.Mutex
	rangeMu sync.Mutex  // Separate mutex for parallel range reads
}

// Read reads up to len(p) bytes into p.
func (pf *PelicanFile) Read(p []byte) (n int, err error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return 0, fs.ErrClosed
	}

	if !pf.readMode {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("file not opened for reading")}
	}

	// Check read/write mutex
	if pf.rdwrMutex && pf.hasWritten {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("cannot read after writing in read-write mode")}
	}
	pf.hasRead = true

	// If this is a collection/directory, return an error
	if pf.fileInfo != nil && pf.fileInfo.IsCollection {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("is a directory")}
	}

	// For the first read at position 0, start a transfer using the TransferEngine
	if !pf.transferStarted && pf.position == 0 {
		return pf.startTransferRead(p)
	}

	// If we have an active transfer pipe and position matches transfer offset, read from it
	if pf.readPipe != nil && pf.position == pf.transferOffset {
		n, err = pf.readPipe.Read(p)
		pf.position += int64(n)
		pf.transferOffset += int64(n)
		return n, err
	}

	// Otherwise, use HTTP range requests for partial reads
	return pf.rangeRead(p, pf.position)
}

// startTransferRead initiates a full file transfer using the TransferEngine with a pipe
func (pf *PelicanFile) startTransferRead(p []byte) (int, error) {
	// Create a pipe for the transfer
	pr, pw := io.Pipe()
	pf.readPipe = pr
	pf.writePipe = pw
	pf.transferDone = make(chan struct{})
	pf.transferStarted = true
	pf.transferOffset = 0

	// Create a transfer job with the pipe writer
	tj, err := pf.transferClient.NewTransferJob(pf.ctx, pf.pUrl.GetRawUrl(), "", false, false, WithWriter(pw))
	if err != nil {
		pw.Close()
		return 0, err
	}
	pf.transferJob = tj

	if err := pf.transferClient.Submit(tj); err != nil {
		pw.Close()
		return 0, err
	}

	// Read the first chunk
	n, err := pf.readPipe.Read(p)
	
	// Check if pipe was closed - indicates transfer completion or error
	if err == io.ErrClosedPipe || err == io.EOF {
		// Shutdown client and get results
		pf.mu.Lock()
		results, shutdownErr := pf.transferClient.Shutdown()
		pf.transferResults = results
		pf.mu.Unlock()
		
		if shutdownErr != nil {
			return n, shutdownErr
		}
		
		// Check for transfer errors
		for _, result := range results {
			if result.Error != nil {
				return n, result.Error
			}
		}
	}
	
	pf.position += int64(n)
	pf.transferOffset += int64(n)
	return n, err
}

// rangeRead performs a partial read using HTTP range requests and updates position
func (pf *PelicanFile) rangeRead(p []byte, offset int64) (int, error) {
	if pf.fileInfo != nil && offset >= pf.fileInfo.Size {
		return 0, io.EOF
	}

	n, err := pf.doRangeRead(p, offset)
	if err != nil {
		return n, err
	}

	pf.position += int64(n)
	return n, nil
}

// doRangeRead performs the actual HTTP range request without updating position
// This doesn't hold the main mutex, allowing parallel range reads
func (pf *PelicanFile) doRangeRead(p []byte, offset int64) (int, error) {
	pf.rangeMu.Lock()
	defer pf.rangeMu.Unlock()

	// Calculate the range to read
	length := int64(len(p))
	if pf.fileInfo != nil && offset+length > pf.fileInfo.Size {
		length = pf.fileInfo.Size - offset
	}

	// Try the sticky endpoint first, then fall back to others
	endpoints := pf.dirResp.ObjectServers
	if len(endpoints) == 0 {
		return 0, errors.New("no object servers available")
	}

	// Get current endpoint atomically
	currentIdx := int(pf.currentEndpoint.Load())
	
	// Reorder to try current endpoint first
	tryOrder := make([]*url.URL, len(endpoints))
	copy(tryOrder, endpoints)
	if currentIdx > 0 && currentIdx < len(tryOrder) {
		// Move current endpoint to front
		tryOrder[0], tryOrder[currentIdx] = tryOrder[currentIdx], tryOrder[0]
	}

	var lastErr error
	for idx, objServer := range tryOrder {
		transferUrl := *objServer
		transferUrl.Path = pf.pUrl.Path

		// Create HTTP request with range header
		req, err := http.NewRequestWithContext(pf.ctx, http.MethodGet, transferUrl.String(), nil)
		if err != nil {
			lastErr = err
			continue
		}

		// Set range header
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))

		// Set authorization if needed
		if pf.tokenContents != "" {
			req.Header.Set("Authorization", "Bearer "+pf.tokenContents)
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

		// Check status code
		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			lastErr = errors.Errorf("unexpected status code: %d", resp.StatusCode)
			continue
		}

		// Read the response body
		n, err := io.ReadFull(resp.Body, p[:length])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			lastErr = err
			continue
		}

		// Update sticky endpoint on success (atomically)
		if idx != 0 {
			// Find the original index of this endpoint
			for origIdx, ep := range endpoints {
				if ep.String() == objServer.String() {
					pf.currentEndpoint.Store(int32(origIdx))
					break
				}
			}
		}

		return n, nil
	}

	if lastErr != nil {
		return 0, errors.Wrap(lastErr, "failed to download range from all object servers")
	}

	return 0, errors.New("no object servers available")
}

// ReadAt reads len(p) bytes into p starting at offset off in the file.
// It implements io.ReaderAt. Note: ReadAt does not affect the file position.
func (pf *PelicanFile) ReadAt(p []byte, off int64) (n int, err error) {
	// Note: We don't lock pf.mu here to allow parallel ReadAt calls
	if pf.closed {
		return 0, fs.ErrClosed
	}

	if !pf.readMode {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("file not opened for reading")}
	}

	if pf.fileInfo != nil && pf.fileInfo.IsCollection {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("is a directory")}
	}

	if off < 0 {
		return 0, &fs.PathError{Op: "read", Path: pf.name, Err: errors.New("negative offset")}
	}

	if pf.fileInfo != nil && off >= pf.fileInfo.Size {
		return 0, io.EOF
	}

	// Use HTTP range request - don't update position as per io.ReaderAt contract
	return pf.doRangeRead(p, off)
}

// Write writes len(p) bytes from p to the file.
// It implements io.Writer.
func (pf *PelicanFile) Write(p []byte) (n int, err error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return 0, fs.ErrClosed
	}

	if !pf.writeMode {
		return 0, &fs.PathError{Op: "write", Path: pf.name, Err: errors.New("file not opened for writing")}
	}

	// Check read/write mutex
	if pf.rdwrMutex && pf.hasRead {
		return 0, &fs.PathError{Op: "write", Path: pf.name, Err: errors.New("cannot write after reading in read-write mode")}
	}

	// Enforce linear writes - no skipping bytes
	if pf.hasWritten && pf.position != pf.writePosition {
		return 0, &fs.PathError{Op: "write", Path: pf.name, Err: errors.New("non-linear writes not supported - cannot skip bytes")}
	}

	pf.hasWritten = true

	// Start transfer on first write
	if !pf.transferStarted {
		if err := pf.startTransferWrite(); err != nil {
			return 0, err
		}
	}

	// Write to the pipe
	n, err = pf.writePipe.Write(p)
	pf.position += int64(n)
	pf.writePosition += int64(n)
	return n, err
}

// startTransferWrite initiates an upload using the TransferEngine with a pipe
func (pf *PelicanFile) startTransferWrite() error {
	// Create a pipe for the transfer
	pr, pw := io.Pipe()
	pf.readPipe = pr  // Engine reads from this
	pf.writePipe = pw // We write to this
	pf.transferDone = make(chan struct{})
	pf.transferStarted = true
	pf.writePosition = 0

	// Create a transfer job with the pipe reader
	tj, err := pf.transferClient.NewTransferJob(pf.ctx, pf.pUrl.GetRawUrl(), "", true, false, WithReader(pr))
	if err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	pf.transferJob = tj

	if err := pf.transferClient.Submit(tj); err != nil {
		pr.Close()
		pw.Close()
		return err
	}

	return nil
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
		if pf.fileInfo == nil {
			return 0, &fs.PathError{Op: "seek", Path: pf.name, Err: errors.New("cannot seek from end without file size")}
		}
		newPos = pf.fileInfo.Size + offset
	default:
		return 0, &fs.PathError{Op: "seek", Path: pf.name, Err: errors.New("invalid whence")}
	}

	if newPos < 0 {
		return 0, &fs.PathError{Op: "seek", Path: pf.name, Err: errors.New("negative position")}
	}

	// Don't close the transfer pipe - client may come back to this position
	// Just update our position tracking
	pf.position = newPos
	return pf.position, nil
}

// ReadDir reads the contents of the directory and returns a slice of DirEntry values.
// It implements fs.ReadDirFile. Can be called multiple times to paginate through entries.
func (pf *PelicanFile) ReadDir(n int) ([]fs.DirEntry, error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return nil, fs.ErrClosed
	}

	if pf.fileInfo == nil || !pf.fileInfo.IsCollection {
		return nil, &fs.PathError{Op: "readdir", Path: pf.name, Err: errors.New("not a directory")}
	}

	// Fetch entries on first call
	if pf.dirEntries == nil {
		// Use listHttp directly instead of DoList to reuse cached dirResp and token
		fileInfos, err := listHttp(pf.pUrl, pf.dirResp, pf.token, false, 0)
		if err != nil {
			return nil, &fs.PathError{Op: "readdir", Path: pf.name, Err: err}
		}

		// Convert FileInfo to DirEntry
		pf.dirEntries = make([]fs.DirEntry, 0, len(fileInfos))
		for _, fi := range fileInfos {
			pf.dirEntries = append(pf.dirEntries, &pelicanDirEntry{
				name:  fi.Name,
				isDir: fi.IsCollection,
				size:  fi.Size,
				mtime: fi.ModTime,
			})
		}
		pf.dirEntriesRead = 0
	}

	// Return remaining entries
	remaining := len(pf.dirEntries) - pf.dirEntriesRead
	if remaining == 0 {
		return nil, io.EOF
	}

	// Handle n parameter
	if n <= 0 {
		// Return all remaining entries
		entries := pf.dirEntries[pf.dirEntriesRead:]
		pf.dirEntriesRead = len(pf.dirEntries)
		return entries, nil
	}

	// Return up to n entries
	end := pf.dirEntriesRead + n
	if end > len(pf.dirEntries) {
		end = len(pf.dirEntries)
	}
	
	entries := pf.dirEntries[pf.dirEntriesRead:end]
	pf.dirEntriesRead = end
	
	return entries, nil
}

// Stat returns the FileInfo structure describing the file.
// It implements fs.File.
func (pf *PelicanFile) Stat() (fs.FileInfo, error) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if pf.closed {
		return nil, fs.ErrClosed
	}

	if pf.fileInfo == nil {
		// For write-only files, we may not have stat info
		return &pelicanFileInfo{
			name:    filepath.Base(pf.name),
			size:    pf.writePosition,
			modTime: time.Now(),
			isDir:   false,
		}, nil
	}

	return &pelicanFileInfo{
		name:    filepath.Base(pf.name),
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

	// Close the write pipe if open (signals EOF to upload)
	if pf.writePipe != nil {
		pf.writePipe.Close()
		pf.writePipe = nil
	}

	// Close the read pipe if it's open
	if pf.readPipe != nil {
		pf.readPipe.Close()
		pf.readPipe = nil
	}

	// Shutdown the transfer client and engine, get results with mutex held
	var err error
	if pf.transferClient != nil && pf.transferStarted {
		// Check if we already have results (from earlier shutdown)
		if pf.transferResults == nil {
			results, shutdownErr := pf.transferClient.Shutdown()
			pf.transferResults = results
			if shutdownErr != nil {
				err = shutdownErr
			}
			
			// Check for transfer errors in results
			if err == nil {
				for _, result := range results {
					if result.Error != nil {
						err = result.Error
						break
					}
				}
			}
		} else {
			// Use cached results
			for _, result := range pf.transferResults {
				if result.Error != nil {
					err = result.Error
					break
				}
			}
		}
	}
	
	if pf.transferEngine != nil {
		pf.transferEngine.Shutdown()
	}

	// Return any transfer error or cached error
	if err != nil {
		return err
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
func (pfi *pelicanFileInfo) Mode() fs.FileMode  { 
	if pfi.isDir {
		return fs.ModeDir | 0755
	}
	return 0644
}
func (pfi *pelicanFileInfo) ModTime() time.Time { return pfi.modTime }
func (pfi *pelicanFileInfo) IsDir() bool        { return pfi.isDir }
func (pfi *pelicanFileInfo) Sys() interface{}   { return nil }

// pelicanDirEntry implements fs.DirEntry for directory listings
type pelicanDirEntry struct {
	name  string
	isDir bool
	size  int64
	mtime time.Time
}

func (pde *pelicanDirEntry) Name() string { return pde.name }
func (pde *pelicanDirEntry) IsDir() bool  { return pde.isDir }
func (pde *pelicanDirEntry) Type() fs.FileMode {
	if pde.isDir {
		return fs.ModeDir
	}
	return 0
}
func (pde *pelicanDirEntry) Info() (fs.FileInfo, error) {
	return &pelicanFileInfo{
		name:    pde.name,
		size:    pde.size,
		modTime: pde.mtime,
		isDir:   pde.isDir,
	}, nil
}
