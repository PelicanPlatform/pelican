//go:build !windows

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

package oa4mp

import (
	"os/exec"
	"syscall"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

func customizeCmd(cmd *exec.Cmd) error {
	if config.IsRootExecution() {
		user, err := config.GetOA4MPUser()
		if err != nil {
			return errors.Wrap(err, "Unable to launch bootstrap script as OA4MP user")
		}

		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(user.Uid), Gid: uint32(user.Gid)}
	}
	return nil
}
