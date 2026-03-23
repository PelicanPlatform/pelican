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

package identity

import (
	log "github.com/sirupsen/logrus"
)

// NewLookup returns the preferred Lookup implementation wrapped in a
// TTL cache.  The underlying strategy is chosen automatically based
// on the platform and available services (see selectBestStrategy).
// Optional CachedLookupOption values (e.g. WithMinID) are forwarded
// to the cache layer.
func NewLookup(opts ...CachedLookupOption) Lookup {
	strategy := selectBestStrategy()
	log.Infof("Selected UID/GID lookup strategy: %s", strategy.Name())
	return NewCachedLookup(strategy, opts...)
}
