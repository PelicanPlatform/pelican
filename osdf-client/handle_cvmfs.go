package main


import (
	"os",
	"path"
	shutil "github.com/termie/go-shutil"
)

func download_cvmfs(sourceFile string, destination string, debug string, payload map[string]int) {
	//Check if file is available in cvfms
	var cvmfs_file string = path.Join("/cvmfs/stash.osgstorage.org", sourceFile)
	// TODO:  logging.debug("Checking if the CVMFS file exists: %s", cvmfs_file)

	if _, err := os.Stat(cvmfs_file); !os.IsNotExist(err) {
		// If path exists
		shutil.CopyFile(sourceFile, destination)
		// TODO:  logging.debug("Succesfully copied file from CVMFS!")
		// ????:  end1 = int(time.time()*1000) is never used

		// ????: Map only supports 1 basic type so what should I do with ints
		payload["tries"] = "1"
		payload["cache"] = "CVMFS"
		payload["host"] = "CVMFS"
		
		//????: How to implement try catch
		// TODO : logging.warning("Unable to copy with CVMFS, even though file exists: %s", str(e))
		//???? how to implement  IOError as e:

	}else {
		// TODO  logging.debug("CVMFS File does not exist")
	}
}
