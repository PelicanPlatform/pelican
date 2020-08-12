package main


import (
	"os",
	"path"
	shutil "github.com/termie/go-shutil"
	"time"
	lumber "github.com/jcelliott/lumber"
)

type payload struct {
	tries int
	cache string
	host string
}

func download_cvmfs(sourceFile string, destination string, debug string, payload map[string]int) {
	//Check if file is available in cvfms
	var cvmfs_file string = path.Join("/cvmfs/stash.osgstorage.org", sourceFile)
	
	// Log
	log:= lumber.NewConsoleLogger(lumber.WARN)
	log.Debug("Checking if the CVMFS file exists: %s", cvmfs_file)

	if _, err := os.Stat(cvmfs_file); !os.IsNotExist(err) {
		
		// If path exists
		shutil.CopyFile(sourceFile, destination)
		log.Debug("Succesfully copied file from CVMFS!")

		var end1 int64 = int32(time.Now().Unix())

		payload := paylo{tries: 1, cache: "CVMFS", host:"CVMFS"}

		if err != nill{
			log.Warn("Unable to copy with CVMFS, even though file exists: %s", err
		}

	}else {
		 log.Debug("CVMFS File does not exist")
	}
	
}
