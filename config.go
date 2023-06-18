package pelican

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

var (
	isRootExec bool
)

func init () {
	userObj, err := user.Current()
	isRootExec = err == nil && userObj.Username == "root"
}

func GetPreferredPrefix() string {
	arg0 := strings.ToUpper(filepath.Base(os.Args[0]))
	underscore_idx := strings.Index(arg0, "_")
	if underscore_idx != -1 {
		return arg0[0:underscore_idx]
	}
	if strings.HasPrefix(arg0, "STASH") {
		return "STASH"
	} else if strings.HasPrefix(arg0, "OSDF") {
		return "OSDF"
	}
	return "PELICAN"
}

func IsRootExecution() bool {
	return isRootExec
}
