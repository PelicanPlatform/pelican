package main

import (
	"errors"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
	shutil "github.com/termie/go-shutil"
)

func download_cvmfs(sourceFile string, destination string, payload *payloadStruct) error {
	//Check if file is available in cvfms
	var cvmfs_file string = path.Join("/cvmfs/stash.osgstorage.org", sourceFile)

	// Log
	log.Debugf("Checking if the CVMFS file exists: %s", cvmfs_file)

	if _, err := os.Stat(cvmfs_file); !os.IsNotExist(err) {

		// If path exists
		shutil.CopyFile(sourceFile, destination, true)
		log.Debug("Succesfully copied file from CVMFS!")

		//	var end1 int32 = int32(time.Now().Unix())

		//	payload := payloadStruct{tries: 1, cache: "CVMFS", host: "CVMFS"}

		if err != nil {
			log.Warnf("Unable to copy with CVMFS, even though file exists: %s", err)
			return err
		}

	} else {
		log.Debugf("CVMFS File does not exist")
		return errors.New("CVMFS File does not exist")
	}
	return nil
}
