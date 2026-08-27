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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 ***************************************************************/

package xrootd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// The XRootD binary is a startup requirement only for servers that
// actually launch one. Native origin backends and the v2 cache run
// in-process, so demanding the binary would make it a hard dependency of
// deployments that never use it.
func TestServerLaunchesXrootd(t *testing.T) {
	for _, tc := range []struct {
		name        string
		storageType string
		cacheV2     bool
		server      server_structs.XRootDServer
		want        bool
	}{
		{name: "posix origin launches xrootd", storageType: "posix", server: &origin.OriginServer{}, want: true},
		{name: "s3 origin launches xrootd", storageType: "s3", server: &origin.OriginServer{}, want: true},
		{name: "posixv2 origin is native", storageType: "posixv2", server: &origin.OriginServer{}, want: false},
		{name: "pstore origin is native", storageType: "pstore", server: &origin.OriginServer{}, want: false},
		{name: "s3v2 origin is native", storageType: "s3v2", server: &origin.OriginServer{}, want: false},
		{name: "globusv2 origin is native", storageType: "globusv2", server: &origin.OriginServer{}, want: false},
		{name: "v1 cache launches xrootd", cacheV2: false, server: &cache.CacheServer{}, want: true},
		{name: "v2 cache is native", cacheV2: true, server: &cache.CacheServer{}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, param.Reset())
			defer func() { require.NoError(t, param.Reset()) }()
			settings := map[string]any{"Cache.EnableV2": tc.cacheV2}
			if tc.storageType != "" {
				settings["Origin.StorageType"] = tc.storageType
			}
			require.NoError(t, param.MultiSet(settings))
			assert.Equal(t, tc.want, serverLaunchesXrootd(tc.server))
		})
	}
}
