package main

import (
	"errors"
	"io"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
)

func download_cvmfs(sourceFile string, destination string, payload *payloadStruct) (int64, error) {
	//Check if file is available in cvfms
	var cvmfs_file string = path.Join("/cvmfs/stash.osgstorage.org", sourceFile)

	// Log
	log.Debugf("Checking if the CVMFS file exists: %s", cvmfs_file)

	if _, err := os.Stat(cvmfs_file); !os.IsNotExist(err) {

		// If path exists
		in, err := os.Open(cvmfs_file)
		if err != nil {
			log.Debugln("Failed to open the source file:", err)
			return 0, err
		}
		defer in.Close()

		out, err := os.Create(destination)
		if err != nil {
			log.Debugln("Failed to create destination file:", err)
			return 0, err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		if err != nil {
			log.Debugln("Copy of file failed:", err)
			return 0, err
		}
		err = out.Close()
		if err != nil {
			log.Debugln("Error while closing output file:", err)
			return 0, err
		}
		log.Debug("Succesfully copied file from CVMFS!")

		//	var end1 int32 = int32(time.Now().Unix())

		//	payload := payloadStruct{tries: 1, cache: "CVMFS", host: "CVMFS"}

		if err != nil {
			log.Warnf("Unable to copy with CVMFS, even though file exists: %s", err)
			return 0, err
		}

	} else {
		log.Debugf("CVMFS File does not exist")
		return 0, errors.New("CVMFS File does not exist")
	}

	// Get the size of the destination
	dest_stat, err := os.Stat(destination)
	if err != nil {
		return 0, err
	}
	return dest_stat.Size(), nil
}
