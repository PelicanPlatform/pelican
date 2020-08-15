package main

import (
	"os/exec"
	lumber "github.com/jcelliott/lumber"
)

func download_xrootd(nearest_cache string, nearest_cache_list, sourceFile string, destination string, payload map[string]int){

	// Download from the nearest cache, if that fails, fallback to the stash origin.

	// Check for xrootd, return quickly if it's not available
	if check_for_xrootd() == false{
		return false
	}

	// If the cache is not specified by the command line, then look for the closest

	// if nearest_cache.Size() == 0{
	// 	nearest_cache = get_best_stashcache()
	// }
	// cache = nearest_cache; (TODO: nearest cache not implemented yet)
}

func check_for_xrootd(){

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
		log.Fatal(err)
	}
	if err := command_object.Start(); err != nil {
		log.Fatal(err)
	}
	if err := command_object.Wait(); err != nil {
		log.Fatal(err)
	}
	// return command output(xrdcp version)

	xrdcp_version, err := command_object.StdoutPipe()
	if nil != err {
		log.Fatalf("Error obtaining stdout: %s", err.Error())
	}

	if err := command_object.Wait(); err != nil {
        if exiterr, ok := err.(*exec.ExitError); ok {
            // The program has exited with an exit code != 0
        if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			log.Debug("xrdcp command returned exit code: %d", status.ExitStatus())
       		return false
            }
        } else {
            logging.Debug("xrdcp version: %s", xrdcp_version)
       	 	return xrdcp_version
        }
    }
}

