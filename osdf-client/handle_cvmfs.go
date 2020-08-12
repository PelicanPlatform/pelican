package main

import (
	"os"
	"path"

	lumber "github.com/jcelliott/lumber"
	shutil "github.com/termie/go-shutil"
)

type payloadStruct struct {
	tries int
	cache string
	host  string
}

func download_cvmfs(sourceFile string, destination string, payload payloadStruct) {
	//Check if file is available in cvfms
	var cvmfs_file string = path.Join("/cvmfs/stash.osgstorage.org", sourceFile)

	// Log
	log := lumber.NewConsoleLogger(lumber.WARN)
	log.Debug("Checking if the CVMFS file exists: %s", cvmfs_file)

	if _, err := os.Stat(cvmfs_file); !os.IsNotExist(err) {

		// If path exists
		shutil.CopyFile(sourceFile, destination, true)
		log.Debug("Succesfully copied file from CVMFS!")

		//	var end1 int32 = int32(time.Now().Unix())

		//	payload := payloadStruct{tries: 1, cache: "CVMFS", host: "CVMFS"}

		if err != nil {
			log.Warn("Unable to copy with CVMFS, even though file exists: %s", err)
		}

	} else {
		log.Debug("CVMFS File does not exist")
	}

}
