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

package local_cache

import (
	"context"
	"io"
	"syscall"

	"github.com/pelicanplatform/pelican/client"
)

// transferStopKeepsData reports whether a transfer that ended in err before
// the end of what it was asked for left whole blocks fit to keep.
//
// It is an allowlist, so that it fails safe: only a cause known to say
// nothing about the bytes already delivered qualifies --
//
//   - the cache stopping the transfer itself: an idle cancel, the cache
//     shutting down, or a reader that gave up (context.Canceled; every
//     context these transfers run under is the cache's own), or a transfer
//     client that went away without reporting;
//   - the transport breaking: a connection reset, a timeout, a transfer
//     the client judged too slow or stalled, or a body cut short (an
//     unexpected EOF from the connection itself).
//
// Anything else condemns the data, including every failure a server
// reported about the transfer -- an error status, or a failure in the
// X-Transfer-Status trailer, which a cache upstream sends when its own
// verification of the object fails -- a checksum mismatch, a change of
// version, and any error not recognised here.  When a transfer made several
// attempts, every attempt's error must qualify.
func transferStopKeepsData(err error) bool {
	if err == nil {
		return false
	}
	if isBenignStopCause(err) {
		return true
	}
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		errs := u.Unwrap()
		if len(errs) == 0 {
			return false
		}
		for _, e := range errs {
			if !transferStopKeepsData(e) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return transferStopKeepsData(u.Unwrap())
	}
	return false
}

// isBenignStopCause reports whether err itself -- not anything it wraps --
// is one of the causes transferStopKeepsData accepts.  Looking at one link
// of the chain at a time matters: a trailer that reads "unexpected EOF" is
// wrapped as a client.UnexpectedEOFError around the server's text, and must
// not pass for the connection's own io.ErrUnexpectedEOF.
func isBenignStopCause(err error) bool {
	switch err {
	case errAdoptedTransferIdle, errAdoptedTransferUnreported, errPrefetchIdle,
		context.Canceled, io.ErrUnexpectedEOF,
		syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE:
		return true
	}
	switch e := err.(type) {
	case *client.NetworkResetError, *client.SlowTransferError,
		*client.StoppedTransferError, *client.HeaderTimeoutError:
		return true
	case interface{ Timeout() bool }:
		// net.Error timeouts, os.ErrDeadlineExceeded and
		// context.DeadlineExceeded.
		return e.Timeout()
	}
	return false
}

// endWrite closes the writer a transfer fed, according to how the transfer
// ended (err is its error, nil on success): Close on success, StopEarly when
// it stopped for a reason that says nothing against its data, and Abort
// otherwise.  A writer that cannot stop early or abort is closed.
func endWrite(w io.Closer, err error) error {
	if err == nil {
		return w.Close()
	}
	if s, ok := w.(interface{ StopEarly() }); ok && transferStopKeepsData(err) {
		s.StopEarly()
		return nil
	}
	if a, ok := w.(interface{ Abort() }); ok {
		a.Abort()
		return nil
	}
	return w.Close()
}
