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

package config

import (
	"math"
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
		var uid uint64
		uid, result.err = strconv.ParseUint(uidString, 10, 32)
		if result.err != nil {
			result.Uid = -1
			return result
		}
		// On 32-bit systems, converting from uint32 to int may overflow
		if uid > math.MaxInt {
			result.Uid = -1
			result.err = errors.New("UID value overflows on 32-bit system")
			return result
		}
		result.Uid = int(uid)
		result.Sid = userObj.Gid
		//group is just the whole SID
		result.Groupname = userObj.Gid
	} else { //Mac and linux have similar enough uid's so can group them here
		var uid uint64
		uid, result.err = strconv.ParseUint(userObj.Uid, 10, 32)
		if result.err != nil {
			result.Uid = -1
			return result
		}
		if uid > math.MaxInt {
			result.Uid = -1
			result.err = errors.New("UID value overflows on 32-bit system")
			return result
		}
		result.Uid = int(uid)
		var gid uint64
		gid, result.err = strconv.ParseUint(userObj.Gid, 10, 32)
		if result.err != nil {
			result.Gid = -1
			return result
		}
		if gid > math.MaxInt {
			result.Uid = -1
			result.err = errors.New("GID value overflows on 32-bit system")
			return result
		}
		result.Gid = int(gid)
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

func GetDaemonUserInfo() (User, error) {
	return xrootdUser, xrootdUser.err
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
