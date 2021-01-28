package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"syscall"

	//"net/http"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"time"
	
	// "crypto/sha1"
	// "encoding/hex"
	// "strings"
	lumber "github.com/jcelliott/lumber"
)

// Redirector
var global_redirector string = "http://redirector.osgstorage.org:8000"
var cache_host string = "http://hcc-stash.unl.edu:8000/"
var VERSION string = "5.6.2"

var nearest_cache string
var nearest_cache_list []string
var caches_list_name string = ""
var caches_json_location string = ""
var token_location string = ""
var print_cache_list_names = false

type payloadStruct struct {
	filename string
	sitename string
	status   string
	Owner    string
	ProjectName string
	start1   int64
	end1 	 int64
	timestamp int64
	downloadTime int64
	fileSize int64 
	downloadSize int64
}

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
	/* 
	Options from stashcache:
	--parser.add_option('-d', '--debug', dest='debug', action='store_true', help='debug')
    parser.add_option('-r', dest='recursive', action='store_true', help='recursively copy')
    parser.add_option('--closest', action='store_true', help="Return the closest cache and exit")
    --parser.add_option('-c', '--cache', dest='cache', help="Cache to use")
    parser.add_option('-j', '--caches-json', dest='caches_json', help="A JSON file containing the list of caches",
                      default=None)
    parser.add_option('-n', '--cache-list-name', dest='cache_list_name', help="Name of pre-configured cache list to use",
                      default=None)
    parser.add_option('--list-names', dest='list_names', action='store_true', help="Return the names of pre-configured cache lists and exit (first one is default for -n)")
    parser.add_option('--methods', dest='methods', help="Comma separated list of methods to try, in order.  Default: cvmfs,xrootd,http", default="cvmfs,xrootd,http")
    parser.add_option('-t', '--token', dest='token', help="Token file to use for reading and/or writing")
	*/

	usage := "usage: %prog [options] source destination"


	// stashcp --debug
	// stashcp -d
	// Sets variable debug = true
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Debug output")

	// Cache option
	var cache string
	flag.StringVar(&cache, "cache", "", "Cache to use")

	// Caches json
	var cache_json string
	flag.StringVar(&cache_json, "caches-json","","A json file")

	var closest bool 
	flag.StringVar(&closest, "closest", false, "Return the closest cache")

	var listNames bool
	flag.StringVar(&listNames, "list-names", false, "Return the names of pre-configured cache lists and exit") 
	
	//cache list name
	// file path to a file that contains a list of caches to use
	var cacheListName string  
	flag.StringVar(&cacheListName, "cache-list-name", "", "Name of cache list to use")


	//list of methods
	var methods string
	flag.StringVar(methods, "methods", "cvmfs,xrootd,http", "Comma separated list of methods")

	//Token file
	var token string
	flag.StringVar(token, "token", "","Token file to use for reading")

	// Just return all the caches that it knows about
	// Print out all of the caches and exit
	if listNames {
        print_cache_list_names = true
		get_best_stashcache()
		exit(0)
	}

	if closest {
		fmt.Println(get_best_stashcache())
		os.Exit(0)
	}

	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Printf("Must have at least 2 arguments\n")
		os.Exit(1)
	}

	source := args[0]
	dest := args[1]

	// Test all flags
	if debug {
		// Set logging to debug level

	}



	if args.caches_json {
		caches_json_location = caches_json

	} else if val, jsonPresent := os.LookupEnv("CACHES_JSON"); jsonPresent {
		caches_json_location = val
	} else {
		prefix = os.Getenv("OSG_LOCATION", "/")
		caches_file = filepath.Join(prefix, "etc/stashcache/caches.json")
		if _, err := os.Stat(caches_file); err == nil {
			caches_json_location = caches_file
		}
	}
	
	caches_list_name = args.cache_list_name


	// Check for manually entered cache to use ??
	nearestCache,nearestCacheIsPresent := os.LookupEnv("NEAREST_CACHE")
	
	if nearestCacheIsPresent {
		append(nearest_cache_list, nearest_cache)
	} else if args.cache {
		nearest_cache = args.cache
		append(nearest_cache_list, cache)
	}

	if args.token {
		token_location = args.token
	}

	// Convert the methods
	splitMethods := Strings.split(methods, ",")

	// get absolute path
	destPath, _ := filepath.Abs(dest)
	var destFinal string

	//Check if path exists or if its in a folder
	if destStat, err := os.Stat(destPath); os.IsNotExist(err) {
		destFinal = destPath
	} else if destStat.IsDir() {
		// Get the file name of the source
		sourceFilename := path.Base(source)
		destFinal = path.Join(destPath, sourceFilename)
	}

	if !args.recursive {
		result := doStashCPSingle(source, destFinal, splitMethods)
	}
	
	// Exit with failure
	os.Exit(result)
}

func doWriteBack(source string, destination string, debug bool) /*unsure of return type*/ {
	/*
			  Do a write back to Stash using SciTokens

		    :param str source: The location of the local file
		    :param str destination: The location of the remote file, in stash:// format
	*/

	start1 := int(time.Now()*1000)
	
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
	
	


}

func getToken() (string, error) {
	log := lumber.NewConsoleLogger(lumber.WARN)
	// Get the token / scitoken from the environment in order to read/write

	// Get the scitoken content
	scitoken_file := ""

	type tokenJson struct {
		accessKey string `json`
		
	}
	/* 
		Search for the location of the authentiction token.  It can be set explicitly on the command line (TODO),
		with the environment variable "TOKEN", or it can be searched in the standard HTCondor directory pointed 
		to by the environment variable "_CONDOR_CREDS".
	*/


	if token_location == "" {
		// https://golang.org/pkg/os/#LookupEnv
		tokenFile, isTokenSet := os.LookupEnv("TOKEN")
		credsDir, isCondorCredsSet := os.LookupEnv("_CONDOR_CREDS")
		
		// Backwards compatibility for getting scitokens
		// If TOKEN is not set in environment, and _CONDOR_CREDS is set, then...
		if isTokenSet {
			token_location = tokenFile
		} else if !isTokenSet && isCondorCredsSet {
			// Token wasn't specified on the command line or environment, try the default scitoken
			if _, err := os.Stat(filepath.Join(credsDir, "scitokens.use")); os.IsNotExist(err) {
				token_location = filepath.Join(credsDir,"scitokens.use" )
			} else if _, err := os.Stat(".condor_creds/scitokens.use"); os.IsNotExist(err) {
				token_location = filepath.Abs(".condor_creds/scitokens.use")
			}
		} else {
			// Print out, can't find token!  Print out error and exit with non-zero exit status
			// TODO: Better error message
			return "", error.New("Failed to find token...")
		}

	}

	//Read in the JSON
	log.Debug("Opening file: " + token_location)
    tokenContents, _ := ioutil.ReadFile(filename)
	if err := json.Unmarshal(tokenContents, &) err != nil {
		log.Debug("JSON failed. Falling back to old style scitoken parsing")
		scitoken_file, err = file.Seek(0,0)
		if err != nil {
			log.Fatal(err)
		}


	}
	return scitoken_file
}

func doStashCPSingle(sourceFile string, destination string, methods []string){

	// Parse the source and destination with URL parse
	
	source_url := url.Parse(sourceFile)
	dest_url := url.Parse(destination)

	var understodSchemes string[] = ["stash","file",""]
	

	_, foundSource = Find(understoodSchemes, source_url.Scheme)
	if !found {
		logging.error("Do not understand scheme: %s", source_url.scheme)
		return 1
	}

	_, foundDest = Find(understoodSchemes, source_url.Scheme)
	if !foundDest {
		logging.error("Do not understand scheme: %s", dest_url.scheme)
		return 1
	} 
	
	if dest_url.scheme == "stash"{
		return doWriteBack(source_url.path, dest_url.path, debug)	
	}

	if dest_url.scheme == "file"{
		destination = dest_url.path
	}

	if source_url.scheme == "stash"{
	sourceFile = source_url.path
	}

	if not sourceFile[0] == "/" {
		sourceFile = "/" + sourceFile
	}



	sitename, found := os.LookupEnv("OSG_SITE_NAME")
	if (!found) {
		sitename = "siteNotFound"
	}


	//Fill out the payload as much as possible

	filename = destination + "/" + string.Split(sourceFile, "/")

	// ??
	

	payload := payloadStruct{filename: sourceFile, sitename: OSG_SITE_NAME}

	parse_job_ad(payload)
	




	start1 = tie.Now()
	log := lumber.NewConsoleLogger(lumber.WARN)

	// Go thru the download methods
	
	cur_method = method[0]
	success := false

	// switch statement?
	for _, method := range methods {

		switch method {
		case "cvmfs":
			log.Info("Trying CVMFS...")
			if  download_cvmfs(sourceFile, destination, debug, payload){
				sucess = true
				break
				//check if break still works
			}
		case "xrootd":
			log.Info("Trying XROOTD...")
			if download_xrootd(sourceFile, destination, debug, payload){
				success = true
				break
			}
		case "http":
			log.Info("Trying HTTP...")
			if download_http(sourceFile, destination, debug, payload){
				success = true
				break
			}
		default:
			log.error("Unknown transfer method: %s", method)
		}
	}
			
	end1 := time.Now()

	payload := payloadStruct{filename: sourceFile, sitename: OSG_SITE_NAME, 
							start1: start1, end1: end1, timestamp: end1, downloadTime: (end1 - start1)}

	if success {
		payload := payloadStruct{filename: sourceFile, sitename: OSG_SITE_NAME, status: "Sucess" 
			start1: start1, end1: end1, timestamp: end1, downloadTime: (end1 - start1)}
	
		// Get the final size of the download file

		if destination.IsDir() {
			destination += "/"
		}

		dest_dir, dest_filename  := filepath.Split(destination)
		
		if dest_filename {
			final_destination = destination
		} else {
			final_destination = path.Join(dest_dir, path.Base(sourceFile))
		}

		info, err := os.Stat(final_destination)
		if err != nil {
			return err
		}
		destSize := info.Size()
		// ?? redudancy
		payload.status = "Success"
		payload = payloadStruct{filename: sourceFile, sitename: OSG_SITE_NAME, status: "Sucess",
			start1: start1, end1: end1, timestamp: end1, downloadTime: (end1 - start1),
			fileSize: destSize, downloadSize: destSize}
	} else{
		log.Error("All methods failed! Unable to download file.")
        payload := {status: "Fail"}
	} 

	if es_send(payload) {
		return 0
	}else {
		return 1
	}
}
 

// Find takes a slice and looks for an element in it. If found it will
// return it's key, otherwise it will return -1 and a bool of false.
// From https://golangcode.com/check-if-element-exists-in-slice/
func Find(slice []string, val string) (int, bool) {
    for i, item := range slice {
        if item == val {
            return i, true
        }
    }
    return -1, false
}

// Return list of cache URLS
func get_json_caches(caches_json_location string) []string {

	log := lumber.NewConsoleLogger(lumber.WARN)

	type cachesListMap struct {
		status string
		name   int
	}

	// myMap := map[int][]cachesListMap{}

	f, _ := ioutil.ReadFile(filename)
	var caches_list cachesListMap
	err := json.Unmarshal(f, &caches_list)

	if err != nil {
		log.Error("No cache names found in %s without zero status", caches_json_location)
	}

	log.Debug("Loaded caches list from %s", caches_json_location)

	usable_caches := []string{}

	for _, cache := range caches_list {
		if caches_list.status == 0 {
			usable_caches = append(usable_caches, caches_list.name)
		}
	}

	if len(usable_caches) == 0 {
		log.Error("No cache names found in %s without zero status", caches_json_location)
	}

	return usable_caches

}

func get_ips(name string) []string {
	var ipv4s []string

	var ipv6s []string

	log := lumber.NewConsoleLogger(lumber.WARN)

	info, err := net.LookupHost(name)
	if err != nil {
		log.Error("Unable to look up %s", name)

		var empty []string
		return empty
	}

	for _, tuple := range info {

		if tuple[0] == syscall.AF_INET {
			ipv4s = append(ipv4s, tuple[4][0])
		} else if tuple[0] == syscall.AF_INET6 {
			ipv6s = append(ipv4s, tuple[4][0])
		}
	}

	//Randomize the order of each
	rand.Shuffle(len(ipv4s), func(i, j string) { ipv4s[i], ipv4s[j] = ipv4s[j], ipv4s[i] })
	rand.Shuffle(len(ipv6s), func(i, j string) { ipv6s[i], ipv6s[j] = ipv6s[j], ipv6s[i] })

	// Always prefer IPv4
	return ipv4s + ipv6s

}

func parse_job_ad(payload payloadStruct){ // TODO: needs the payload

	//Parse the .job.ad file for the Owner (username) and ProjectName of the callee.

	condorJobAd, isPresent := os.LookupEnv("_CONDOR_JOB_AD")
	if isPresent { 
		filename := condorJobAd
	} else if _, err := os.Stat(".job.ad"); err == nil {
		filename := ".job.ad"
	  
	} else {
		return 
	}

	// https://stackoverflow.com/questions/28574609/how-to-apply-regexp-to-content-in-file-go
	
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(e)
	}

	// Get all matches from file
	classadRegex, e := regexp.Compile(`^\s*(Owner|ProjectName)\s=\s"(.*)"`)
	if e != nil {
    	log.Fatal(e)
	}

	matches := classadRegex.FindAll(b)

	for _, match := range matches {
		if match[0] == "Owner" {
			payload.Owner = match[1]
		} else if match[0] == "ProjectName" {
			payload.ProjectName = match[1]
		}
	}

	

		

}

// NOT IMPLEMENTED
// func doStashcpdirectory(sourceDir string, destination string, methods string){


// 	// ?? sourceItems = to_str(subprocess.Popen(["xrdfs", stash_origin, "ls", sourceDir], stdout=subprocess.PIPE).communicate()[0]).split()
	
// 	// ?? for remote_file in sourceItems:

// 	command2 := "xrdfs " + stash_origin + " stat "+ remote_file + " | grep "IsDir" | wc -l"

// 	//	?? isdir=to_str(subprocess.Popen([command2],stdout=subprocess.PIPE,shell=True).communicate()[0].split()[0])isdir=to_str(subprocess.Popen([command2],stdout=subprocess.PIPE,shell=True).communicate()[0].split()[0])

// 	if isDir != 0 {
// 		result := doStashcpdirectory(remote, destination /*debug variable??*/)
// 	} else {
// 		result := doStashCpSingle(remote_file, destination, methods, debug)
// 	}

// 	// Stop the transfer if something fails
// 	if result != 0 {
// 		return result
// 	}

// 	return 0
// }

func es_send(payload payloadStruct) {
	log := lumber.NewConsoleLogger(lumber.WARN)
	

	// calculate the current timestamp
	timeStamp := int(time.Now())
	payload.timestamp = timestamp

	// convert payload to a JSON string (something with Marshall ...)


	// Send a HTTP POST to collector.atlas-ml.org, with a timeout!
		resp, err := http.Post("http://collector.atlas-ml.org:9951", "application/json", bytes.NewBuffer(jsonStr))
		
		if err != nil {
			log.Warning("Can't get collector.atlas-ml.org")
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
	// Convert the payload to json
	// ?? not sure how to do this
	// Timeout is set to 5 seconds
    // or this??

	/* Define this function inside ??
	 def _es_send(payload):
        data = payload
        data=json.dumps(data)
        try:
            url = "http://collector.atlas-ml.org:9951"
            req = Request(url, data=data.encode("utf-8"), headers={'Content-Type': 'application/json'})
            f = urlopen(req)
            f.read()
            f.close()
        except (URLError, UnicodeError) as e:
            logging.warning("Error posting to ES: %s", str(e))
	*/

	/*
	    p = multiprocessing.Process(target=_es_send, name="_es_send", args=(payload,))
    	p.start()
    	p.join(5)
   		p.terminate()
	*/


}

// timedTransfer goes in handle xrootd and call is made internally !!

func timed_transfer(filename string, destination string){

	//Transfer the filename from the cache to the destination using xrdcp

	// All these values can be found the xrdc man page

	os.Setenv("XRD_REQUESTTIMEOUT","1")
	os.Setenv("XRD_CPCHUNKSIZE","8388608")
	os.Setenv("XRD_TIMEOUTRESOLUTION","5")
	os.Setenv("XRD_CONNECTIONWINDOW","30")
	os.Setenv("XRD_CONNECTIONRETRY","2")
	os.Setenv("XRD_STREAMTIMEOUT","30")

	if !strings.HasPrefix(filename, "/")/*?? Correct not use?*/ {
		filepath += cache + ":1094//" + filename
	} else {
		filepath := cache+":1094/"+ filename
	}

	if debug {
		command := "xrdcp -d 2 --nopbar -f " + filepath + " " + destination
	}else{
		command := "xrdcp --nopbar -f " + filepath + " " + destination
	}

	filename = "./" + strings.split(filename, "/")

	if fileExists(filename){
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