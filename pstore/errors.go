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

package pstore

import (
	"io/fs"
	"syscall"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
)

// Sentinel errors.  These alias the syscall/fs values the afero and WebDAV
// layers already understand, so that errors.Is(err, fs.ErrNotExist),
// os.IsNotExist, and the handler's status mapping all work without
// translation.
var (
	// ErrNotExist is returned when a path has no entry.
	ErrNotExist = fs.ErrNotExist
	// ErrExist is returned when a path already has an entry and the caller
	// required that it not.
	ErrExist = fs.ErrExist
	// ErrNotDir is returned when a path component is not a directory.
	ErrNotDir = syscall.ENOTDIR
	// ErrIsDir is returned when a directory is used where a file is required.
	ErrIsDir = syscall.EISDIR
	// ErrNotEmpty is returned when a non-recursive removal targets a
	// directory that still has entries.
	ErrNotEmpty = syscall.ENOTEMPTY
	// ErrNoSpace is returned when a write would exceed the store's capacity.
	//
	// golang.org/x/net/webdav reports any failed write as 405 Method Not
	// Allowed, so the origin rewrites the status itself: see
	// origin_serve.statusForBackendError, which turns this into 507
	// Insufficient Storage.
	ErrNoSpace = syscall.ENOSPC
	// ErrInvalidPath is returned for paths the index cannot represent.
	ErrInvalidPath = fs.ErrInvalid
	// ErrNotSupported is returned for operations pstore deliberately does not
	// implement, such as writing at an arbitrary offset.
	ErrNotSupported = errors.New("operation not supported by pstore")
	// ErrDraining is returned when a path is inside a subtree that a
	// recursive delete has removed but the janitor has not finished
	// reclaiming.  Retrying shortly succeeds; the janitor speeds up while a
	// backlog exists.  origin_serve.statusForBackendError reports it as 409
	// Conflict, which is what tells a client the retry is worth making.
	ErrDraining = errors.New("path is still being reclaimed")
	// ErrPreconditionFailed is returned when a conditional write's
	// precondition does not hold -- that is, when Close finds the object no
	// longer carries the generation the caller required.
	// origin_serve.statusForBackendError reports it as 412 Precondition
	// Failed.
	ErrPreconditionFailed = errors.New("precondition failed")
	// ErrConflict is returned when two writers raced to install the same path
	// and this one's index transaction lost.
	//
	// The store's index is serializable, so a commit that reads an entry
	// another commit is replacing is aborted rather than serialized behind it.
	// Nothing is lost -- the winner's version is installed and the loser's is
	// discarded -- and retrying succeeds.  The WebDAV lock system serializes
	// same-path PUTs before they reach here, so a client normally sees 423
	// Locked instead; this is what a caller using the store directly gets.
	// origin_serve.statusForBackendError reports it as 409 Conflict rather
	// than letting an opaque database error surface as a 500.
	ErrConflict = badger.ErrConflict
	// ErrClosed is returned when a handle is used after Close.
	ErrClosed = fs.ErrClosed
)
