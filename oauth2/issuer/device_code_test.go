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

package issuer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// TestPollingInterval pins the contract the device authorization response depends on: what we
// advertise in the whole-second "interval" field is exactly what GetDeviceCodeSession
// enforces.  Truncating instead of rounding up would advertise less than we enforce, and a
// client that honored the advertised value would be answered with slow_down on its second
// poll and back off far longer than the interval we shaved.
func TestPollingInterval(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure time.Duration
		expected  time.Duration
	}{
		{"unset-uses-the-rfc-default", 0, 5 * time.Second},
		{"whole-seconds-are-kept", 2 * time.Second, 2 * time.Second},
		{"fractional-seconds-round-up", 1500 * time.Millisecond, 2 * time.Second},
		{"sub-second-becomes-one-second", 100 * time.Millisecond, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.ResetConfig()
			t.Cleanup(config.ResetConfig)
			require.NoError(t, param.Issuer_DeviceCodePollingInterval.Set(tc.configure))

			interval := pollingInterval()
			assert.Equal(t, tc.expected, interval)
			// The advertised field is this same value, so it must survive the trip
			// through whole seconds unchanged.
			assert.Equal(t, interval, time.Duration(int(interval/time.Second))*time.Second)
		})
	}
}
