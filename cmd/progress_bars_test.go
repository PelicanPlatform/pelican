//go:build client || server

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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

// Both configuration knobs have to suppress progress bars. Each used to be
// spelled out at every call site, which is how a caller comes to honor one and
// forget the other.
func TestProgressBarsEnabled(t *testing.T) {
	cases := []struct {
		name        string
		logLocation string
		disabled    bool
		want        bool
	}{
		{name: "default", want: true},
		// A log file means the display cannot have stdout to itself.
		{name: "log location set", logLocation: "/tmp/pelican-test.log", want: false},
		{name: "explicitly disabled", disabled: true, want: false},
		{name: "both", logLocation: "/tmp/pelican-test.log", disabled: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			test_utils.InitClient(t, map[param.Param]any{
				param.Logging_LogLocation:                tc.logLocation,
				param.Logging_Client_DisableProgressBars: tc.disabled,
			})

			assert.Equal(t, tc.want, progressBarsEnabled())

			// Whatever stdout is in this process, configuration saying no is
			// final: shouldDisplayProgressBars can only be more restrictive.
			if !tc.want {
				assert.False(t, shouldDisplayProgressBars(),
					"configuration that forbids bars must forbid them everywhere")
			}
		})
	}
}

// Under `go test` stdout is not a character device, so the terminal condition
// alone settles it -- which is the other half of the gate.
func TestShouldDisplayProgressBarsRequiresTerminal(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{
		param.Logging_LogLocation:                "",
		param.Logging_Client_DisableProgressBars: false,
	})

	require.True(t, progressBarsEnabled())
	assert.False(t, shouldDisplayProgressBars(),
		"a non-terminal stdout must suppress bars even when configuration allows them")
}
