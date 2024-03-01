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

package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthStatusString(t *testing.T) {
	expectedStrings := [...]string{"critical", "warning", "ok", "unknown"}

	t.Run("health-status-string-handles-out-of-range-index", func(t *testing.T) {
		invalidIndex := len(expectedStrings) + 1
		for idx := range expectedStrings {
			assert.Equal(t, expectedStrings[idx], HealthStatusEnum(idx+1).String())
		}
		require.Equal(t, statusIndexErrorMessage, HealthStatusEnum(invalidIndex).String())
	})
}
