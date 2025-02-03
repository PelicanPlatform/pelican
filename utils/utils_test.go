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

package utils

import (
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateWatermark(t *testing.T) {
	// Can't use config.ResetConfig() due to circ dependency
	viper.Reset()
	defer viper.Reset()

	t.Parallel()
	testCases := []struct {
		name          string
		wm            string
		requireSuffix bool
		hasSuffix     bool
		expectAbs     bool
		expectErr     bool
	}{
		{
			name:          "empty-value",
			wm:            "",
			requireSuffix: false,
			hasSuffix:     false,
			expectAbs:     false,
			expectErr:     true,
		},
		{
			name:          "string-value",
			wm:            "foo",
			requireSuffix: false,
			hasSuffix:     false,
			expectAbs:     false,
			expectErr:     true,
		},
		{
			name:          "percentage-valid-dec",
			wm:            "10.5",
			requireSuffix: false,
			hasSuffix:     false,
			expectAbs:     false,
			expectErr:     false,
		},
		{
			name:          "percentage-valid-int",
			wm:            "100",
			requireSuffix: false,
			hasSuffix:     false,
			expectAbs:     false,
			expectErr:     false,
		},
		{
			name:          "percentage-negative",
			wm:            "-1",
			requireSuffix: false,
			hasSuffix:     false,
			expectAbs:     false,
			expectErr:     true,
		},
		{
			name:          "percentage-greater-than-100",
			wm:            "101",
			requireSuffix: false,
			hasSuffix:     false,
			expectAbs:     false,
			expectErr:     true,
		},
		{
			name:          "k-suffix",
			wm:            "1.1k",
			requireSuffix: false,
			hasSuffix:     true,
			expectAbs:     true,
			expectErr:     false,
		},
		{
			name:          "m-suffix",
			wm:            "1.1m",
			requireSuffix: false,
			hasSuffix:     true,
			expectAbs:     true,
			expectErr:     false,
		},
		{
			name:          "g-suffix",
			wm:            "1.1g",
			requireSuffix: false,
			hasSuffix:     true,
			expectAbs:     true,
			expectErr:     false,
		},
		{
			name:          "t-suffix",
			wm:            "1.1t",
			requireSuffix: false,
			hasSuffix:     true,
			expectAbs:     true,
			expectErr:     false,
		},
		{
			name:          "bad-suffix",
			wm:            "1.1v",
			requireSuffix: false,
			hasSuffix:     true,
			expectAbs:     false,
			expectErr:     true,
		},
		{
			name:          "has-suffix-require-suffix",
			wm:            "1.1g",
			requireSuffix: true,
			hasSuffix:     true,
			expectAbs:     true,
			expectErr:     false,
		},
		{
			name:          "no-suffix-require-suffix",
			wm:            "1.1",
			requireSuffix: true,
			hasSuffix:     false,
			expectAbs:     false,
			expectErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set(tc.name, tc.wm)
			val, isAbs, err := ValidateWatermark(tc.name, tc.requireSuffix)
			if tc.expectErr {
				assert.Equal(t, 0.0, val)
				assert.False(t, isAbs)
				assert.Error(t, err)
				// test is over
				return
			}

			var compVal float64
			if tc.hasSuffix {
				suffix := tc.wm[len(tc.wm)-1]
				compVal, err = strconv.ParseFloat(tc.wm[:len(tc.wm)-1], 64)
				require.NoError(t, err, "Failed to parse the test's watermark value -- this is a bug in the test")
				switch suffix {
				case 'k':
					compVal = compVal * 1024
				case 'm':
					compVal = compVal * 1024 * 1024
				case 'g':
					compVal = compVal * 1024 * 1024 * 1024
				case 't':
					compVal = compVal * 1024 * 1024 * 1024 * 1024
				default:
					assert.Fail(t, "Invalid suffix in test case")
				}
			} else {
				compVal, err = strconv.ParseFloat(tc.wm, 64)
				require.NoError(t, err, "Failed to parse the test's watermark value -- this is a bug in the test")
			}

			assert.Equal(t, compVal, val)
			assert.Equal(t, tc.expectAbs, isAbs)
		})
	}
}
