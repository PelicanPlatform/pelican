//go:build !windows

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

package config

import "os"

// warnIfJWKSFileWorldWritable logs a warning when the JWKS file at path is
// writable by users other than its owner and group.
//
// Every key in the file is published as trusted for its namespace, so write
// access to it is authority to mint accepted tokens. This warns rather than
// refuses: taking a namespace's keys away over a permission bit would be a
// worse outcome than serving them with a loud complaint.
//
// A file that is no longer world-writable clears the record of the earlier
// warning, so that a mode tightened and later loosened back to the same value
// is reported both times. Nothing is cleared for a file that cannot be
// stat'ed: the caller never reaches this in that case, and a file that is
// missing says nothing about the permissions it will come back with.
func warnIfJWKSFileWorldWritable(path string, perm os.FileMode) {
	if perm&0o002 == 0 {
		// The signature below is the mode, and a tightened file returns here
		// without reaching the logger, so without this nothing would ever
		// record that the condition cleared.
		jwksWorldWritableIssue(path).forget()
		return
	}
	jwksWorldWritableIssue(path).warnOnChange(perm.String(),
		"JWKS file %s is world-writable (mode %#o). Every key it holds is published "+
			"as a trusted signing key, so any local user can mint tokens this server "+
			"will accept. Restrict it to mode 0640 or tighter.", path, perm)
}
