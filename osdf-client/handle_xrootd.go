package main

import (
	"bytes"
	"os/exec"
	"syscall"

	lumber "github.com/jcelliott/lumber"
)



func download_xrootd(nearest_cache string, nearest_cache_list, sourceFile string, destination string, payload map[string]int) bool {

	// Download from the nearest cache, if that fails, fallback to the stash origin.

	// Check for xrootd, return quickly if it's not available
	xrootd_check := check_for_xrootd()
	if xrootd_check == "error" {
		return false
	}

	// If the cache is not specified by the command line, then look for the closest
	

	// if nearest_cache.Size() == 0{
	// 	nearest_cache = get_best_stashcache()
	// }

	// cache = nearest_cache; (TODO: nearest cache not implemented yet)


	return false
}

func check_for_xrootd() string {

	// Check if xrootd is installed by checking if the xrdcp command returns a reasonable output
	var check_command string = "xrdcp -V 2>&1"
	log := lumber.NewConsoleLogger(lumber.WARN)
	log.Debug("Running the command to check of xrdcp existance: %s", check_command)

	// var command_object = exec.Command(check_command, // Todo:stdout=subprocess.PIPE, shell=True)
	//TODO:  var xrdcp_version = command_object.communicate()[0]

	// Run command
	command_object := exec.Command(check_command)
	stdout, err := command_object.StdoutPipe()
	if err != nil {
		log.Debug(err.Error())
	}
	if err := command_object.Start(); err != nil {
		log.Debug(err.Error())
	}
	if err := command_object.Wait(); err != nil {
		log.Debug(err.Error())
	}

	xrdcp_version, err := command_object.StdoutPipe()
	if nil != err {
		log.Debug("Error obtaining stdout: %s", err.Error())
	}

	if err := command_object.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				log.Debug("xrdcp command returned exit code: %d", status.ExitStatus())
				return "error"
			}

		}
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(xrdcp_version)
	xrdcp_version_string := buf.String()
	log.Debug("xrdcp version: %s", xrdcp_version_string)
	//log.Debug("xrdcp version: %s", stdout)

	return xrdcp_version_string
}
