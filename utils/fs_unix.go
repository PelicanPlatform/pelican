//go:build !windows

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

package utils

import (
	"os"
	"syscall"

	"github.com/pkg/errors"
)

// SameFilesystem returns true if both paths reside on the same filesystem
// (i.e. share the same device ID). This is important because rename(2) cannot
// move files across filesystem boundaries (returns EXDEV).
func SameFilesystem(pathA, pathB string) (bool, error) {
	infoA, err := os.Stat(pathA)
	if err != nil {
		return false, errors.Wrapf(err, "unable to stat '%s'", pathA)
	}
	infoB, err := os.Stat(pathB)
	if err != nil {
		return false, errors.Wrapf(err, "unable to stat '%s'", pathB)
	}

	statA, ok := infoA.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.Errorf("unable to get device info for '%s'", pathA)
	}
	statB, ok := infoB.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.Errorf("unable to get device info for '%s'", pathB)
	}

	return statA.Dev == statB.Dev, nil
}
