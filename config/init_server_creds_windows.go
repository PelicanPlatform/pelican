//go:build windows

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

package config

import (
	"os"

	log "github.com/sirupsen/logrus"
)

// checkFileReadableByUser on Windows logs a warning since Unix-style permission
// checking doesn't apply. Windows uses ACLs which have a different permission model.
// The Server.DropPrivileges feature is primarily designed for Unix systems.
func checkFileReadableByUser(filePath string, fileInfo os.FileInfo, puser User) error {
	log.Warnf("Cannot verify ownership of %s on Windows; ensure the pelican user (%s) can read it", filePath, puser.Username)
	return nil
}
