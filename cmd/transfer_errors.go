//go:build client

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

package main

import (
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/error_codes"
)

// classifyTransferFailure maps a failed transfer's error to the process exit
// code and the message shown to the user.
//
// The *PelicanError has to be recovered with errors.As, not errors.Is. The exit
// code and the message live on the instance sitting in the error chain, and
// only As can hand that instance back; Is answers a yes/no question about
// identity with a sentinel, and there is no sentinel here. Comparing against a
// freshly declared PelicanError could therefore never match, so every
// classified failure fell through to exit 1.
//
// Giving PelicanError an Is method would make this worse rather than better: it
// would satisfy the comparison while leaving the target as the zero value,
// whose ExitCode() is 0 -- success, reported for a transfer that failed.
func classifyTransferFailure(err error) (code int, msg string) {
	msg = err.Error()
	// A TransferErrors carries a message assembled for humans; prefer it over
	// the raw chain unless a PelicanError below supplies its own.
	var te *client.TransferErrors
	if errors.As(err, &te) {
		msg = te.UserError()
	}
	var pe *error_codes.PelicanError
	if errors.As(err, &pe) {
		// A PelicanError's exit code already encodes whether it is worth
		// retrying, so it is authoritative on its own.
		return pe.ExitCode(), pe.Error()
	}
	if client.ShouldRetry(err) {
		return Retryable, msg
	}
	return 1, msg
}

// exitTransferFailure reports a failed transfer and terminates with the exit
// code its error class calls for. The prefix is the "Failure getting <url>"
// style lead-in; the classified message is appended to it.
//
// Both lines reach stderr even when Logging.LogLocation is redirecting the log
// to a file, so the reason for a non-zero exit is never invisible.
func exitTransferFailure(err error, prefix string) {
	code, msg := classifyTransferFailure(err)
	if code == Retryable {
		reportError(prefix + ": " + msg)
		exitWithError(code, "Errors are retryable")
	}
	exitWithError(code, prefix+": "+msg)
}
