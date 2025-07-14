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

package launchers

import (
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

func dropPrivileges() (err error) {
	log.Info("Dropping privileges to user ", param.Server_UnprivilegedUser.GetString())
	var puser config.User
	puser, err = config.GetPelicanUser()
	if err != nil {
		return
	}
	if puser.Uid == 0 {
		err = errors.Errorf("unable to drop privileges to user (%s) with UID 0", puser.Username)
		return
	}
	if puser.Gid == 0 {
		err = errors.Errorf("unable to drop privileges to user (user %s, group %s) with GID 0", puser.Username, puser.Groupname)
		return
	}
	if err = syscall.Setgid(puser.Gid); err != nil {
		err = errors.Wrap(err, "failed to drop group privileges")
		return
	}
	if err = syscall.Setuid(puser.Uid); err != nil {
		err = errors.Wrap(err, "failed to drop user privileges")
		return
	}
	return
}
