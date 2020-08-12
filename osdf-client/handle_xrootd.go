package main


import (
	"os",
	"os/exec"
	"path"
	
)

func download_xrootd(nearest_cache string, nearest_cache_list, sourceFile string, destination string, payload map[string]int)){

	// Download from the nearest cache, if that fails, fallback to the stash origin.

	// Check for xrootd, return quickly if it's not available
	if check_for_xrootd == false{
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
	check_command string = "xrdcp -V 2>&1"

	//TODO:   logging.debug("Running the command to check of xrdcp existance: %s", check_command)

	 var command_object = exec.Command(check_command, // Todo:stdout=subprocess.PIPE, shell=True)
	//TODO:  var xrdcp_version = command_object.communicate()[0]

	if command_object.returncode == 0 {
	 //	TODO: logging.debug("xrdcp version: %s", xrdcp_version)
	 return xrdcp_version
	} else{
		//TODO: logging.debug("xrdcp command returned exit code: %i", command_object.returncode)
		return false
	}
}