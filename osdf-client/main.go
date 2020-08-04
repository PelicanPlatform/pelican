package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	
)

// Redirector
var global_redirector string = "http://redirector.osgstorage.org:8000"
var cache_host string = "http://hcc-stash.unl.edu:8000/"
var VERSION string = "5.6.2"

func main() {

	// Basic flag declarations are available for string,
	// integer, and boolean options. Here we declare a
	// string flag `word` with a default value `"foo"`
	// and a short description. This `flag.String` function
	// returns a string pointer (not a string value);
	// we'll see how to use this pointer below.
	//wordPtr := flag.String("cache", "", "The cache to use")
	//debug := flag.Bool("debug", false, "Debug output")

	// This declares `numb` and `fork` flags, using a
	// similar approach to the `word` flag.
	//numbPtr := flag.Int("numb", 42, "an int")
	//boolPtr := flag.Bool("fork", false, "a bool")

	// It's also possible to declare an option that uses an
	// existing var declared elsewhere in the program.
	// Note that we need to pass in a pointer to the flag
	// declaration function.
	//var svar string
	//flag.StringVar(&svar, "svar", "bar", "a string var")

	// Once all flags are declared, call `flag.Parse()`
	// to execute the command-line parsing.
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Printf("Must have at least 2 arguments\n")
		os.Exit(1)
	}
	source := args[0]
	dest := args[1]

	// Combine the paths
	srcURL, _ := url.Parse(cache_host)
	srcURL.Path = path.Join(srcURL.Path, source)

	// get absolute path
	destPath, _ := filepath.Abs(dest)
	var destFinal string

	//Check if path exists or if its in a folder
	if destStat, err := os.Stat(destPath); os.IsNotExist(err) {
		fmt.Println("file does not exist")
		destFinal = destPath
	} else if destStat.IsDir() {
		// Get the file name of the source
		sourceFilename := path.Base(source)
		destFinal = path.Join(destPath, sourceFilename)
	}

	fmt.Printf("url=" + srcURL.String() + " dest=" + destFinal + "\n")
	if err := DownloadHTTP(srcURL.String(), destFinal); err != nil {
		fmt.Printf("Download failed")
	}
	
	//fmt.Printf("Trying URL: %v\n", u.String())
	//redir := GetRedirect(u.String())
	//fmt.Printf("ERROR: %v\n", redir)

	// Started Here

	/*

	userAgent := "stashcp/" + VERSION

	main_redirector := "root://redirector.osgstorage.org"
	stash_origin := "root://stash.osgconnect.net"
	writeback_host := "http://stash-xrd.osgconnect.net:1094"

//Global variable for nearest cache
	nearest_cache :=  ""// ?? what type

// Ordered list of nearest caches  ***************************************
	nearest_cache_list := []int{}

// Global variable for the location of the caches.json file
	caches_json_location := ""

// Global variable for the name of a pre-configured cache list
	cache_list_name := ""

// Global variable for the location of the token to use for reading / writing
	token_location := ""

// Global variable to print names of cache lists
	print_cache_list_names := ""

	TIMEOUT := 300
	DIFF    := TIMEOUT * 10

	*/

	

}


func doWriteBack(source string,destination string,debug bool) /*unsure of return type*/{
	/*
	  Do a write back to Stash using SciTokens

    :param str source: The location of the local file
    :param str destination: The location of the remote file, in stash:// format
	*/

	//start1 := int(time.Now()*1000)
	/*
	scitoken_contents := ""//getToken()
	if scitoken_contents == getToken() { 
		errors.New("Unable to find scitokens.use file")
		return
	}

	if debug == true {
		output_mode := "-v"
	} else {
		output_mode := "-s"
	}
	*/
	/* Commented out for now

	//Check if the source file is zero-length
	statinfo := os.Stat(source)
	
	if statinfo.Size() == 0 {  //CHECK After rsoolving compilation error Size method should be in OS or Syscall
		speed_time = "--speed-time 5 "	
	} else {
		speed_time := ""
	}
	command := fmt.Sprintf("curl %s --connect-timeout 30 %s--speed-limit 1024 -X PUT --fail --upload-file %s -H \"User-Agent: %s\" -H \"Authorization: Bearer %s\" %s%s",output_mode, speed_time, source, user_agent, scitoken_contents, writeback_host, destination)
	
	val, present := os.LookupEnv("http_proxy")
	if present { // replace with go in method
		(os.Environ).Clearenv()
	}
	*/





}

func getToken() string {
	// Get the token / scitoken from the environment in order to read/write

	// Get the scitoken content
	//scitoken_file := ""

	/*
	// command line
	if token_location {
		scitoken_file = token_location
	}
	*/

	//if 'TOKEN'
	return ""
}
