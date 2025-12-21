/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package daemon

import "sync/atomic"

var expectedRestart atomic.Bool

// SetExpectedRestart marks whether a XRootD restart is currently in progress.
func SetExpectedRestart(inProgress bool) {
	expectedRestart.Store(inProgress)
}

// IsExpectedRestart reports whether daemon shutdowns should be treated as
// intentional because a restart is underway.
func IsExpectedRestart() bool {
	return expectedRestart.Load()
}
