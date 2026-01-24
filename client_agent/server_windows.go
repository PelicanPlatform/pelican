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

//go:build windows

package client_agent

import (
	log "github.com/sirupsen/logrus"
)

// verifyDirectoryOwnership checks that the directory is owned by the specified user
// On Windows, we can't easily verify ownership in the same way, so we just log a warning
func verifyDirectoryOwnership(path string, expectedUID int) error {
	log.Warn("Database directory ownership verification not implemented on Windows")
	return nil
}
