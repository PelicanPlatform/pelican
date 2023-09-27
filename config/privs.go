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
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

var (
	isRootExec bool

	uidErr      error
	gidErr      error
	sidErr      error
	usernameErr error
	groupErr    error

	uid      int
	gid      int
	sid      string
	username string
	group    string
)

func init() {
	userObj, err := user.Current()
	isRootExec = err == nil && userObj.Username == "root"

	uid = -1
	gid = -1
	sid = ""
	if err != nil {
		uidErr = err
		gidErr = err
		sidErr = err
		usernameErr = err
		groupErr = err
		return
	}
	desiredUsername := userObj.Username
	if isRootExec {
		desiredUsername = "xrootd"
		userObj, err = user.Lookup(desiredUsername)
		if err != nil {
			err = errors.Wrap(err, "Unable to lookup the xrootd runtime user"+
				" information; does the xrootd user exist?")
			uidErr = err
			gidErr = err
			usernameErr = err
			groupErr = err
			return
		}
	}
	//Windows has userId's different from mac and linux, need to parse to get it
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		//Get the user ID from the SID
		sidParts := strings.Split(userObj.Uid, "-")
		uidString := sidParts[len(sidParts)-1]
		uid, err = strconv.Atoi(uidString)
		if err != nil {
			uid = -1
			uidErr = err
		}
		sid = userObj.Gid
		//group is just the whole SID
		group = userObj.Gid
	} else { //Mac and linux have similar enough uid's so can group them here
		uid, err = strconv.Atoi(userObj.Uid)
		if err != nil {
			uid = -1
			uidErr = err
		}
		gid, err = strconv.Atoi(userObj.Gid)
		if err != nil {
			gid = -1
			gidErr = err
		}
		groupObj, err := user.LookupGroupId(userObj.Gid)
		if err == nil {
			group = groupObj.Name
		} else {
			// Fall back to using the GID as the group name.  This is done because,
			// currently, the group name is just for logging strings.  The group name
			// lookup often fails because we've disabled CGO and only CGO will use the
			// full glibc stack to resolve information via SSSD.
			//
			// This decision should be revisited if we ever enable CGO.
			group = userObj.Gid
		}
	}
	// username same for both windows, linux, and mac
	username = desiredUsername
}

func IsRootExecution() bool {
	return isRootExec
}

func GetDaemonUID() (int, error) {
	return uid, uidErr
}

func GetDaemonUser() (string, error) {
	return username, usernameErr
}

func GetDaemonGID() (int, error) {
	return gid, gidErr
}

func GetDaemonSID() (string, error) {
	return sid, sidErr
}

func GetDaemonGroup() (string, error) {
	return group, groupErr
}
