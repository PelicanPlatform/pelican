package config

import (
	"os/user"
	"strconv"

	"github.com/pkg/errors"
)

var (
	isRootExec bool

	uidErr      error
	gidErr      error
	usernameErr error
	groupErr    error

	uid      int
	gid      int
	username string
	group    string
)

func init() {
	userObj, err := user.Current()
	isRootExec = err == nil && userObj.Username == "root"

	uid = -1
	gid = -1
	if err != nil {
		uidErr = err
		gidErr = err
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
	username = desiredUsername
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

func GetDaemonGroup() (string, error) {
	return group, groupErr
}
