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

package client

import (
	"fmt"
	"math/rand"
	"path/filepath"
)

// Convert b bytes to a human-friendly string with SI units
//
// For example, ByteCountSI(2000) returns "2 KB"
func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

// generateTempPath creates a temporary filename for a transfer
// Uses rsync-style naming: .basename.XXXXXX where X is a random alphanumeric character
func generateTempPath(finalPath string) string {
	dir := filepath.Dir(finalPath)
	base := filepath.Base(finalPath)
	suffix := generateRandomSuffix(6)
	return filepath.Join(dir, fmt.Sprintf(".%s.%s", base, suffix))
}

// generateRandomSuffix creates a random alphanumeric string of the specified length
func generateRandomSuffix(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
