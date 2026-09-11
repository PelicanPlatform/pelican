//go:build windows

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

// warnIfJWKSFileWorldWritable does nothing on Windows, where access is governed
// by ACLs that os.FileInfo does not expose. Go synthesizes the permission bits
// from the read-only attribute alone, reporting 0666 for every writable file
// and 0444 for every read-only one, so the "other write" bit would warn about
// every JWKS file on the system while saying nothing about who can actually
// write it.
func warnIfJWKSFileWorldWritable(path string, perm os.FileMode) {}
