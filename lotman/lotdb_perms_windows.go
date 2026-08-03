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

package lotman

import "os"

// The V1 (XRootD) deployment model does not exist on Windows -- there is no
// separate daemon user to share the lot database with -- so these are the
// permissions the file gets created with and nothing is widened.
const lotDBFileMode os.FileMode = 0o660

const lotDBDirMode os.FileMode = 0o770

// secureSharedLotDB is a no-op on Windows: POSIX ownership does not apply, and
// there is no purge plugin running as another user to share the database with.
func secureSharedLotDB(_ string, _, _ int) error { return nil }
