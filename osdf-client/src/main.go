package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"time"
	"syscall"
	"context"
	"errors"
	
	
)

// Redirector
var global_redirector string = "http://redirector.osgstorage.org:8000"

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
	//dest := args[1]

	// Combine the paths
	u, _ := url.Parse(global_redirector)
	u.Path = path.Join(u.Path, source)

	fmt.Printf("Trying URL: %v\n", u.String())
	redir := GetRedirect(u.String())
	fmt.Printf("ERROR: %v\n", redir)

	// Started Here

	VERSION := "5.6.2"
	user_agent := "stashcp/"
	user_agent = append(user_agent, VERSION)

	main_redirector := "root://redirector.osgstorage.org"
	stash_origin := "root://stash.osgconnect.net"
	writeback_host := "http://stash-xrd.osgconnect.net:1094"

//Global variable for nearest cache
	nearest_cache :=  None// ?? what type

// Ordered list of nearest caches  ***************************************
	nearest_cache_list := []int{}

// Global variable for the location of the caches.json file
	caches_json_location := None

// Global variable for the name of a pre-configured cache list
	cache_list_name := None

// Global variable for the location of the token to use for reading / writing
	token_location := None

// Global variable to print names of cache lists
	print_cache_list_names := False

	TIMEOUT := 300
	DIFF    := TIMEOUT * 10



	

}


func doWriteBack(source string,destination string,debug bool) /*unsure of return type*/{
	/*
	  Do a write back to Stash using SciTokens

    :param str source: The location of the local file
    :param str destination: The location of the remote file, in stash:// format
	*/

	start1 := int(time.Now()*1000)

	scitoken_contents := //getToken()
	if scitoken_contents == getToken() { 
		errors.New("Unable to find scitokens.use file")
		return 1
	}

	if debug == true {
		output_mode := "-v"
	} else {
		output_mode := "-s"
	}

	//Check if the source file is zero-length
	statinfo := os.Stat(source)
	
	if statinfo.Size() == 0   //CHECK After rsoolving compilation error Size method should be in OS or Syscall
	{
		speed_time = "--speed-time 5 "	
	} else {
		speed_time := ""
	}
	command := fmt.Sprintf("curl %s --connect-timeout 30 %s--speed-limit 1024 -X PUT --fail --upload-file %s -H \"User-Agent: %s\" -H \"Authorization: Bearer %s\" %s%s",output_mode, speed_time, source, user_agent, scitoken_contents, writeback_host, destination)
	
	if "http_proxy" in os.Environ{ // replace with go in method
		(os.Environ).Clearenv()
	}





}

func getToken(){
	// Get the token / scitoken from the environment in order to read/write

	// Get the scitoken content
	scitoken_file := None

	// command line
	if token_location {
		scitoken_file = token_location
	}

	if 'TOKEN'
}
