/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Helper func to produce server ads for tests
func produceAd(name, adType, vString string) server_structs.ServerAd {
	ad := server_structs.ServerAd{
		ServerBaseAd: server_structs.ServerBaseAd{},
		Type:         adType,
	}
	ad.Initialize(name)
	ad.Version = vString
	return ad
}

func TestServerSupportsFeature(t *testing.T) {
	mockFeature := Feature{
		Name: "MockFeature",
		Origin: map[string]FeatureVersionInfo{
			"v1.0.0": {
				NotBeforePelican: "v7.10",
				NotAfterPelican:  "v7.20",
			},
		},
		Cache: map[string]FeatureVersionInfo{
			"v1.0.0": {
				NotBeforePelican: "v7.15",
				NotAfterPelican:  "v7.25",
			},
		},
	}

	tests := []struct {
		name           string
		serverAd       server_structs.ServerAd
		expectedResult utils.Ternary
	}{
		{
			name:           "Origin server supports feature within range",
			serverAd:       produceAd("OriginServer", server_structs.OriginType.String(), "v7.15"),
			expectedResult: utils.Tern_True,
		},
		{
			name:           "Origin server does not support feature (below range)",
			serverAd:       produceAd("OriginServer", server_structs.OriginType.String(), "v7.05"),
			expectedResult: utils.Tern_False,
		},
		{
			name:           "Origin server does not support feature (above range)",
			serverAd:       produceAd("OriginServer", server_structs.OriginType.String(), "v7.25"),
			expectedResult: utils.Tern_False,
		},
		{
			name:           "Cache server supports feature within range",
			serverAd:       produceAd("CacheServer", server_structs.CacheType.String(), "v7.20"),
			expectedResult: utils.Tern_True,
		},
		{
			name:           "Cache server does not support feature (below range)",
			serverAd:       produceAd("CacheServer", server_structs.CacheType.String(), "v7.0"),
			expectedResult: utils.Tern_False,
		},
		{
			name:           "Cache server does not support feature (above range)",
			serverAd:       produceAd("CacheServer", server_structs.CacheType.String(), "v7.30"),
			expectedResult: utils.Tern_False,
		},
		{
			name:           "Unknown server type",
			serverAd:       produceAd("UnknownServer", "UnknownType", "v7.15"),
			expectedResult: utils.Tern_Unknown,
		},
		{
			name:           "Missing version information",
			serverAd:       produceAd("NoVersionServer", server_structs.OriginType.String(), ""),
			expectedResult: utils.Tern_Unknown,
		},
		{
			name:           "Invalid version format",
			serverAd:       produceAd("InvalidVersionServer", server_structs.CacheType.String(), "invalid_version"),
			expectedResult: utils.Tern_Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ServerSupportsFeature(mockFeature, tt.serverAd)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
