
package main

import (
	"path/filepath"
	"os"
)

func main() {
	exec_name := filepath.Base(os.Args[0])
	if exec_name == "stash_plugin" || exec_name == "osdf_plugin" || exec_name == "pelican_xfer_plugin" {
		stashPluginMain(os.Args[1:])
	} else if exec_name == "stashcp" {
		err := copyCmd.Execute()
		if err != nil {
			os.Exit(1)
		}
	} else {
		Execute()
	}
}

