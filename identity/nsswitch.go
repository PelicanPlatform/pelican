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

package identity

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// NSSSwitchMethod represents a method in nsswitch.conf.
type NSSSwitchMethod string

const (
	// NSSSwitchMethodSSS represents the SSSD method.
	NSSSwitchMethodSSS NSSSwitchMethod = "sss"
	// NSSSwitchMethodFiles represents the files method (traditional /etc/passwd).
	NSSSwitchMethodFiles NSSSwitchMethod = "files"
)

// ParseNSSwitch parses the given nsswitch.conf file and returns the methods
// for the passwd database.  Only "sss" and "files" are recognised; other
// methods are silently ignored.  If no passwd line is found, it defaults to
// []NSSSwitchMethod{NSSSwitchMethodFiles}.
func ParseNSSwitch(path string) ([]NSSSwitchMethod, error) {
	file, err := os.Open(path) // #nosec G304 - path is controlled by configuration
	if err != nil {
		return nil, fmt.Errorf("failed to open nsswitch.conf: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "passwd:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		var methods []NSSSwitchMethod
		for _, part := range parts[1:] {
			// Skip action syntax like [NOTFOUND=return]
			if strings.HasPrefix(part, "[") {
				continue
			}
			switch part {
			case "sss":
				methods = append(methods, NSSSwitchMethodSSS)
			case "files":
				methods = append(methods, NSSSwitchMethodFiles)
			}
		}
		return methods, nil
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading nsswitch.conf: %w", err)
	}

	// No passwd line found — default to files
	return []NSSSwitchMethod{NSSSwitchMethodFiles}, nil
}
