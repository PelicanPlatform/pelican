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

package byte_rate

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ByteRate represents a transfer rate in Bytes/Second.
type ByteRate float64

// Common binary prefixes (Base-2)
const (
	_ = 1.0 << (10 * iota) // Ignore 2^0
	KiB
	MiB
	GiB
	TiB
	PiB
)

// Standard interfaces for easy parsing from configs/flags
func (r *ByteRate) UnmarshalText(text []byte) error {
	rate, err := ParseRate(string(text))
	if err != nil {
		return err
	}
	*r = rate
	return nil
}

// MarshalJSON implements json.Marshaler to output the human-readable format
func (r ByteRate) MarshalJSON() ([]byte, error) {
	return []byte(`"` + r.String() + `"`), nil
}

// String implements fmt.Stringer for nice printing (defaulting to MB/s)
func (r ByteRate) String() string {
	val := float64(r)
	switch {
	case val >= PiB:
		return fmt.Sprintf("%.2fPB/s", val/PiB)
	case val >= TiB:
		return fmt.Sprintf("%.2fTB/s", val/TiB)
	case val >= GiB:
		return fmt.Sprintf("%.2fGB/s", val/GiB)
	case val >= MiB:
		return fmt.Sprintf("%.2fMB/s", val/MiB)
	case val >= KiB:
		return fmt.Sprintf("%.2fKB/s", val/KiB)
	default:
		return fmt.Sprintf("%.2fB/s", val)
	}
}

// ParseRate parses a string like "5MB/s", "100Mbps", or "1GiB/m".
// It returns Bytes Per Second.
func ParseRate(s string) (ByteRate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty rate string")
	}

	// 1. Separate the Magnitude/Size from the Duration
	//    Patterns: "MB/s", "MB/min", "Mbps" (implies /s)
	var sizeStr string
	var duration time.Duration = time.Second // Default to per-second

	if strings.HasSuffix(strings.ToLower(s), "ps") {
		// Handle "Mbps", "Kbps" -> treat as size "Mb", duration 1s
		sizeStr = s[:len(s)-2] // strip "ps"
	} else if idx := strings.Index(s, "/"); idx != -1 {
		// Handle "MB/s", "GB/m"
		sizeStr = s[:idx]
		durStr := s[idx+1:]

		// Normalize shorthand durations for time.ParseDuration
		switch durStr {
		case "s", "sec":
			duration = time.Second
		case "m", "min":
			duration = time.Minute
		case "h", "hr":
			duration = time.Hour
		default:
			// Try parsing standard Go duration (e.g. "500ms")
			// We prepend "1" if the user just wrote "/d" or "/h" to make it "1h"
			if val, err := time.ParseDuration(durStr); err == nil {
				duration = val
			} else if val, err := time.ParseDuration("1" + durStr); err == nil {
				duration = val
			} else {
				return 0, fmt.Errorf("invalid time duration: %s", durStr)
			}
		}
	} else {
		// No slash, no 'ps'. Assume raw bytes? Or implied /s?
		// Usually safer to assume the whole string is the size, implied /s
		sizeStr = s
	}

	// 2. Parse the Size component (Value + Unit)
	// Regex breakdown:
	// ^([\d\.]+)  -> Capture the number (integer or float)
	// \s* -> Allow whitespace
	// ([a-zA-Z]+) -> Capture the unit suffix
	re := regexp.MustCompile(`^([\d\.]+)\s*([a-zA-Z]+)$`)
	matches := re.FindStringSubmatch(sizeStr)

	var value float64
	var unit string

	if matches == nil {
		// Maybe just a number without unit?
		if val, err := strconv.ParseFloat(sizeStr, 64); err == nil {
			value = val
			unit = "B" // default to bytes
		} else {
			return 0, fmt.Errorf("invalid size format: %s", sizeStr)
		}
	} else {
		var err error
		value, err = strconv.ParseFloat(matches[1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid number: %s", matches[1])
		}
		unit = matches[2]
	}

	// 3. Calculate Multiplier based on Unit (Base-2)
	// We normalize to BYTES.
	// if 'b' is present, we divide by 8.

	var multiplier float64
	unit = strings.ToLower(unit)

	// Detect bits vs bytes
	isBits := false
	if matches != nil && (strings.HasSuffix(unit, "bit") || (strings.HasSuffix(unit, "b") && !strings.HasSuffix(unit, "byte"))) {
		// "Mb", "Mbit" -> bits. "MB", "MByte" -> bytes.
		// Note: "b" usually means bits in networking, "B" bytes.
		// Since we lowercased, we check strict suffix logic or original casing if needed.
		// For robustness: if the original string had 'b' at end it's likely bits, 'B' is bytes.
		// Let's look at the LAST character of the match from the regex to be precise.
		originalUnit := matches[2] // preserve case
		lastChar := originalUnit[len(originalUnit)-1]
		if lastChar == 'b' {
			isBits = true
		}
		// Special case: "bit" spelled out
		if strings.HasSuffix(unit, "bit") {
			isBits = true
		}
	}

	// Strip suffix to find magnitude (k, m, g...)
	// We look at the first letter of the unit
	// Handle bare numbers (no unit) - default to bytes
	if unit == "" {
		multiplier = 1.0 // bare number defaults to B/s
	} else {
		prefix := unit[0] // 'k', 'm', etc.

		switch prefix {
		case 'k':
			multiplier = KiB
		case 'm':
			multiplier = MiB
		case 'g':
			multiplier = GiB
		case 't':
			multiplier = TiB
		case 'p':
			multiplier = PiB
		case 'b': // byte or bit (no prefix)
			multiplier = 1.0
		default:
			// If it's something unknown, assume 1 (or error)
			multiplier = 1.0
		}
	}

	totalBytes := value * multiplier

	if isBits {
		totalBytes /= 8.0
	}

	// 4. Final Calculation
	ratePerSec := totalBytes / duration.Seconds()

	return ByteRate(ratePerSec), nil
}
