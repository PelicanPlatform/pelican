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

package origin

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestGetRequiredFeatures(t *testing.T) {
	testCases := []struct {
		name          string
		expectedNames []string
		vConfig       map[string]any
	}{
		{
			name: "No Features",
		},
		{
			name:          "CacheAuthz Feature",
			expectedNames: []string{"CacheAuthz"},
			vConfig: map[string]any{
				param.Origin_DisableDirectClients.GetName(): true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()

			for k, v := range tc.vConfig {
				viper.Set(k, v)
			}

			oServer := &OriginServer{}
			features := oServer.GetRequiredFeatures()
			assert.Equal(t, len(tc.expectedNames), len(features), "Expected number of features to match")
			if len(tc.expectedNames) == 0 {
				return
			}

			featureNames := make([]string, len(features))
			for i, feature := range features {
				featureNames[i] = feature.GetName()
			}

			assert.Equal(t, tc.expectedNames, featureNames, "Expected feature names to match")
		})
	}
}
