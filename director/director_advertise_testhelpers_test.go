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

package director

import "github.com/pelicanplatform/pelican/server_structs"

// newTestDirectorInfo builds a directorInfo with the given ad stored.
// directorInfo.ad is an atomic.Pointer, so it cannot be set via a struct
// literal; tests use this helper instead.  It lives in an unconstrained file
// (no build tag) so it is available to both the platform-agnostic tests
// (e.g. ha_property_test.go) and the !windows tests (e.g. forward_service_test.go).
func newTestDirectorInfo(ad *server_structs.DirectorAd) *directorInfo {
	di := &directorInfo{}
	di.ad.Store(ad)
	return di
}
