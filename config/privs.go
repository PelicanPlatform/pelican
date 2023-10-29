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

type User struct {
	Uid       int
	Gid       int
	Sid       string
	Username  string
	Groupname string
	err       error
}

var (
	isRootExec bool

	xrootdUser User
	oa4mpUser  User
)

func init() {
	userObj, err := user.Current()
	isRootExec = err == nil && userObj.Username == "root"

	xrootdUser = newUser()
	oa4mpUser = newUser()

	if isRootExec {
		xrootdUser = initUserObject("xrootd", nil)
		oa4mpUser = initUserObject("tomcat", nil)
	} else if err != nil {
		xrootdUser.err = err
		oa4mpUser.err = err
	} else {
		xrootdUser = initUserObject(userObj.Username, userObj)
		oa4mpUser = initUserObject(userObj.Username, userObj)
	}
}

func initUserObject(desiredUsername string, userObj *user.User) User {
	result := newUser()
	result.Username = desiredUsername
	if userObj == nil {
		userObjNew, err := user.Lookup(desiredUsername)
		if err != nil {
			err = errors.Wrapf(err, "Unable to lookup the runtime user"+
				" information; does the %s user exist?", desiredUsername)
			result.err = err
			return result
		}
		userObj = userObjNew
	}

	//Windows has userId's different from mac and linux, need to parse to get it
	currentOS := runtime.GOOS
	if currentOS == "windows" {
		//Get the user ID from the SID
		sidParts := strings.Split(userObj.Uid, "-")
		uidString := sidParts[len(sidParts)-1]
		result.Uid, result.err = strconv.Atoi(uidString)
		if result.err != nil {
			result.Uid = -1
			return result
		}
		result.Sid = userObj.Gid
		//group is just the whole SID
		result.Groupname = userObj.Gid
	} else { //Mac and linux have similar enough uid's so can group them here
		result.Uid, result.err = strconv.Atoi(userObj.Uid)
		if result.err != nil {
			result.Uid = -1
			return result
		}
		result.Gid, result.err = strconv.Atoi(userObj.Gid)
		if result.err != nil {
			result.Gid = -1
			return result
		}
		groupObj, err := user.LookupGroupId(userObj.Gid)
		if err == nil {
			result.Groupname = groupObj.Name
		} else {
			// Fall back to using the GID as the group name.  This is done because,
			// currently, the group name is just for logging strings.  The group name
			// lookup often fails because we've disabled CGO and only CGO will use the
			// full glibc stack to resolve information via SSSD.
			//
			// This decision should be revisited if we ever enable CGO.
			result.Groupname = userObj.Gid
		}
	}
	return result
}

func newUser() (userObj User) {
	userObj.Uid = -1
	userObj.Gid = -1
	return
}

func IsRootExecution() bool {
	return isRootExec
}

func GetDaemonUID() (int, error) {
	return xrootdUser.Uid, xrootdUser.err
}

func GetDaemonUser() (string, error) {
	return xrootdUser.Username, xrootdUser.err
}

func GetDaemonGID() (int, error) {
	return xrootdUser.Gid, xrootdUser.err
}

func GetDaemonSID() (string, error) {
	return xrootdUser.Sid, xrootdUser.err
}

func GetDaemonGroup() (string, error) {
	return xrootdUser.Groupname, xrootdUser.err
}

func GetOA4MPUser() (User, error) {
	return oa4mpUser, oa4mpUser.err
}
