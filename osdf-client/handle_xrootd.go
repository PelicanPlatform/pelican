package main

import (
	"bytes"
	"errors"
	"os/exec"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func download_xrootd(sourceFile string, destination string, payload *payloadStruct) error {

	// Download from the nearest cache, if that fails, fallback to the stash origin.

	// Check for xrootd, return quickly if it's not available
	xrootd_check := check_for_xrootd()
	if xrootd_check != nil {
		return xrootd_check
	}

	// If the cache is not specified by the command line, then look for the closest
	if len(nearest_cache_list) == 0 {
		get_best_stashcache()
	}

	// if nearest_cache.Size() == 0{
	// 	nearest_cache = get_best_stashcache()
	// }

	// cache = nearest_cache; (TODO: nearest cache not implemented yet)

	return errors.New("XrootD not implemented")
}

func check_for_xrootd() error {

	// Check if xrootd is installed by checking if the xrdcp command returns a reasonable output
	var check_command string = "xrdcp -V 2>&1"
	log.Debugf("Running the command to check of xrdcp existance: %s", check_command)

	// var command_object = exec.Command(check_command, // Todo:stdout=subprocess.PIPE, shell=True)
	//TODO:  var xrdcp_version = command_object.communicate()[0]

	// Run command
	command_object := exec.Command(check_command)
	if err := command_object.Start(); err != nil {
		log.Debug(err.Error())
		return err
	}

	xrdcp_version, err := command_object.StdoutPipe()
	if nil != err {
		log.Debug("Error obtaining stdout: %s", err.Error())
		return err
	}

	if err := command_object.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				log.Debug("xrdcp command returned exit code: %d", status.ExitStatus())
				return errors.New("xrdcp returned non-zero exit code")
			}

		}
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(xrdcp_version)
	xrdcp_version_string := buf.String()
	log.Debug("xrdcp version: %s", xrdcp_version_string)
	//log.Debug("xrdcp version: %s", stdout)

	return nil
}

// timedTransfer goes in handle xrootd and call is made internally !!
/*
func timed_transfer(filename string, destination string) {

	//Transfer the filename from the cache to the destination using xrdcp

	// All these values can be found the xrdc man page

	os.Setenv("XRD_REQUESTTIMEOUT", "1")
	os.Setenv("XRD_CPCHUNKSIZE", "8388608")
	os.Setenv("XRD_TIMEOUTRESOLUTION", "5")
	os.Setenv("XRD_CONNECTIONWINDOW", "30")
	os.Setenv("XRD_CONNECTIONRETRY", "2")
	os.Setenv("XRD_STREAMTIMEOUT", "30")

	if !strings.HasPrefix(filename, "/") {
		filepath += cache + ":1094//" + filename
	} else {
		filepath := cache + ":1094/" + filename
	}

	if debug {
		command := "xrdcp -d 2 --nopbar -f " + filepath + " " + destination
	} else {
		command := "xrdcp --nopbar -f " + filepath + " " + destination
	}

	filename = "./" + strings.Split(filename, "/")

	if fileExists(filename) {
		e := os.Remove(filename)
	}

	// Set logger globally
	// https://github.com/sirupsen/logrus
	log := lumber.NewConsoleLogger(lumber.WARN)
	log.Debug("xrdcp command: %s", command)
	if debug {
		// Use https://golang.org/pkg/os/exec/

		// ?? xrdcp=subprocess.Popen([command ],shell=True,stdout=subprocess.PIPE)
	} else {
		// ?? xrdcp=subprocess.Popen([command ],shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	}

	//	xrdcp.communicate()
	// xrd_exit=xrdcp.returncode

	return string(xrd_exit)

}
*/
