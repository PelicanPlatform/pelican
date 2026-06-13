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

package lotman

import (
	"math"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// The lotman core stores storage quantities as int64 bytes. The adapter (and
// the REST API and PolicyDefinitions config) speak GB as float64. These helpers
// convert at that boundary, using the same decimal-GB factor the codebase has
// always used (bytesInGigabyte = 1e9, defined in lotman_linux.go).
//
// The unbounded sentinel is preserved across the unit change: -1 GB maps to -1
// bytes (core.Unbounded), NOT to -1e9 bytes. A nil GB pointer means "unset" and
// maps to 0 (callers apply field defaults before conversion).

// gbToBytes converts a GB value to int64 bytes, preserving the unbounded
// sentinel (-1 GB -> -1 bytes).
func gbToBytes(gb float64) int64 {
	if gb == -1 {
		return core.Unbounded
	}
	return int64(math.Round(gb * bytesInGigabyte))
}

// bytesToGB converts int64 bytes to a GB value, preserving the unbounded
// sentinel (-1 bytes -> -1 GB).
func bytesToGB(b int64) float64 {
	if b == core.Unbounded {
		return -1
	}
	return float64(b) / bytesInGigabyte
}

// gbPtrToBytes converts an optional GB value to int64 bytes. A nil pointer maps
// to 0 (the field was not set; defaults are applied upstream).
func gbPtrToBytes(gb *float64) int64 {
	if gb == nil {
		return 0
	}
	return gbToBytes(*gb)
}

// bytesToGBPtr converts int64 bytes to a non-nil *float64 GB value.
func bytesToGBPtr(b int64) *float64 {
	v := bytesToGB(b)
	return &v
}

// int64PtrValue returns the value of an optional Int64FromFloat (object counts
// and millisecond timestamps), with nil mapping to def.
func int64PtrValue(v *Int64FromFloat, def int64) int64 {
	if v == nil {
		return def
	}
	return v.Value
}
