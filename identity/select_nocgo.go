//go:build !cgo

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

// selectBestStrategy chooses the best available lookup strategy.
// Without CGO, Go's os/user only parses /etc/passwd directly,
// so we try specialized strategies first.
func selectBestStrategy() LookupStrategy {
	strategies := []func() (LookupStrategy, error){
		trySystemdUserDB, // systemd-userdbd via varlink
		tryNSSStrategy,   // NSS chain per nsswitch.conf
		tryGoFallback,    // Go's os/user (parses /etc/passwd)
	}

	for _, tryStrategy := range strategies {
		if strategy, err := tryStrategy(); err == nil && strategy != nil {
			return strategy
		}
	}

	// Should not happen — tryGoFallback always succeeds
	panic("no UID/GID lookup strategy available")
}
