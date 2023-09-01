//go:build linux

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"github.com/pkg/errors"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Determine whether the current process has the
// capabilities necessary for running xrootd in multiuser mode.
func HasMultiuserCaps() (result bool, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errors.New("Unable to determine the process's capabilities")
		}
	}()

	curSet := cap.GetProc()
	if curSet == nil {
		// Note: per package documentation, this should never happen; instead,
		// the `GetProc` function should have panic'd...
		return false, errors.New("Unable to determine current capabilities")
	}

	if enabled, err := curSet.GetFlag(cap.Permitted, cap.SETUID); err != nil || !enabled {
		return false, err
	}
	if enabled, err := curSet.GetFlag(cap.Permitted, cap.SETGID); err != nil || !enabled {
		return false, err
	}
	return true, nil
}
