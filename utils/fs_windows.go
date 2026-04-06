//go:build windows

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
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// FileOwnerIDs is not supported on Windows; POSIX uid/gid are not available.
func FileOwnerIDs(_ os.FileInfo) (uid, gid int, err error) {
	return 0, 0, errors.New("POSIX file ownership (uid/gid) is not available on Windows")
}

// SameFilesystem on Windows optimistically returns true. POSIX Origins are not
// meaningfully supported on Windows, so the cross-filesystem check is skipped.
func SameFilesystem(_, _ string) (bool, error) {
	log.Debugln("Skipping same-filesystem check on Windows")
	return true, nil
}
