package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	//"net/http"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"time"

	// "crypto/sha1"
	// "encoding/hex"
	// "strings"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

// Redirector
var global_redirector string = "http://redirector.osgstorage.org:8000"
var cache_host string = "http://hcc-stash.unl.edu:8000/"
var VERSION string = "5.6.2"

// Nearest cache
var nearest_cache string

// List of caches, in order from closest to furthest
var nearest_cache_list []string
var caches_list_name string = ""
var caches_json_location string = ""
var token_location string = ""
var print_cache_list_names = false

type payloadStruct struct {
	filename     string
	sitename     string
	status       string
	Owner        string
	ProjectName  string
	start1       int64
	end1         int64
	timestamp    int64
	downloadTime int64
	fileSize     int64
	downloadSize int64
}

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

type SourceDestination struct {
	Source      string `short:"i" long:"input" description:"Source file" default:"-"`
	Destination string `short:"o" long:"output" description:"Destination file" default:"-"`
}

type Options struct {
	// Turn on the debug logging
	Debug bool `short:"d" long:"debug" description:"Turn on debug logging"`

	// Specify the configuration file
	Closest bool `long:"closest" description:"Return the closest cache and exit"`

	// Cache to use
	Cache string `short:"c" long:"cache" description:"Cache to use"`

	// A JSON file containing the list of caches
	CacheJSON string `short:"j" long:"caches-json" description:"A JSON file containing the list of caches"`

	// Comma separated list of methods to try, in order.  Default: cvmfs,xrootd,http
	Methods string `long:"methods" description:"Comma separated list of methods to try, in order.  Default: cvmfs,xrootd,http" default:"cvmfs,xrootd,http"`

	// Token file to use for reading and/or writing
	Token string `long:"token" short:"t" description:"Token file to use for reading and/or writing"`

	ListCaches bool `long:"list-names" description:"Return the names of pre-configured cache lists and exit"`

	// Positional arguemnts
	SourceDestination SourceDestination `description:"Source and Destination Files" positional-args:"1"`
}

var options Options

var parser = flags.NewParser(&options, flags.Default)

func main() {

	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if options.Debug {
		// Set logging to debug level
		setLogging(log.DebugLevel)
	} else {
		setLogging(log.WarnLevel)
	}

	// Just return all the caches that it knows about
	// Print out all of the caches and exit
	if options.ListCaches {
		print_cache_list_names = true
		get_best_stashcache()
		os.Exit(0)
	}

	if options.Closest {
		fmt.Println(get_best_stashcache())
		os.Exit(0)
	}

	source := options.SourceDestination.Source
	dest := options.SourceDestination.Destination

	/*
		TODO: Parse a caches JSON, is this needed anymore?
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
	*/

	// Check for manually entered cache to use ??
	nearestCache, nearestCacheIsPresent := os.LookupEnv("NEAREST_CACHE")

	if nearestCacheIsPresent {
		nearest_cache = nearestCache
		nearest_cache_list = append(nearest_cache_list, nearest_cache)
	} else if options.Cache != "" {
		nearest_cache = options.Cache
		nearest_cache_list = append(nearest_cache_list, options.Cache)
	}

	if options.Token != "" {
		token_location = options.Token
	}

	// Convert the methods
	splitMethods := strings.Split(options.Methods, ",")

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

	result := doStashCPSingle(source, destFinal, splitMethods)

	// Exit with failure
	if result != nil {
		os.Exit(1)
	}

}

func setLogging(logLevel log.Level) error {
	textFormatter := log.TextFormatter{}
	textFormatter.DisableLevelTruncation = true
	textFormatter.FullTimestamp = true
	log.SetFormatter(&textFormatter)
	log.SetLevel(logLevel)
	return nil
}

/* TODO writeback
func doWriteBack(source string, destination string, debug bool) {
	/*
			  Do a write back to Stash using SciTokens

		    :param str source: The location of the local file
		    :param str destination: The location of the remote file, in stash:// format


	start1 := int(time.Now().Unix() * 1000)

	scitoken_contents := "" //getToken()
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

	if statinfo.Size() == 0 { //CHECK After rsoolving compilation error Size method should be in OS or Syscall
		speed_time = "--speed-time 5 "
	} else {
		speed_time := ""
	}
	command := fmt.Sprintf("curl %s --connect-timeout 30 %s--speed-limit 1024 -X PUT --fail --upload-file %s -H \"User-Agent: %s\" -H \"Authorization: Bearer %s\" %s%s", output_mode, speed_time, source, user_agent, scitoken_contents, writeback_host, destination)

	val, present := os.LookupEnv("http_proxy")
	if present { // replace with go in method
		(os.Environ).Clearenv()
	}

}
*/
func getToken() (string, error) {

	// Get the token / scitoken from the environment in order to read/write

	// Get the scitoken content
	scitoken_file := ""

	type tokenJson struct {
		accessKey string `json:"access_token"`
		expiresIn int    `json:"expires_in"`
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
				token_location = filepath.Join(credsDir, "scitokens.use")
			} else if _, err := os.Stat(".condor_creds/scitokens.use"); os.IsNotExist(err) {
				token_location, _ = filepath.Abs(".condor_creds/scitokens.use")
			}
		} else {
			// Print out, can't find token!  Print out error and exit with non-zero exit status
			// TODO: Better error message
			return "", errors.New("Failed to find token...")
		}

	}

	//Read in the JSON
	log.Debug("Opening file: " + token_location)
	tokenContents, _ := ioutil.ReadFile(token_location)
	tokenParsed := tokenJson{}
	if err := json.Unmarshal(tokenContents, &tokenParsed); err != nil {
		log.Debugln("Error unmarshalling JSON token contents:", err, "Falling back to old style scitoken parsing")
	}
	return scitoken_file, nil
}

func doStashCPSingle(sourceFile string, destination string, methods []string) error {

	// Parse the source and destination with URL parse

	source_url, err := url.Parse(sourceFile)
	if err != nil {
		log.Errorln("Failed to parse source URL:", err)
		return err
	}

	dest_url, err := url.Parse(destination)
	if err != nil {
		log.Errorln("Failed to parse destination URL:", err)
		return err
	}

	understoodSchemes := []string{"stash", "file", ""}

	_, foundSource := Find(understoodSchemes, source_url.Scheme)
	if !foundSource {
		log.Errorln("Do not understand source scheme:", source_url.Scheme)
		return errors.New("Do not understand source scheme")
	}

	_, foundDest := Find(understoodSchemes, source_url.Scheme)
	if !foundDest {
		log.Errorln("Do not understand destination scheme:", source_url.Scheme)
		return errors.New("Do not understand destination scheme")
	}

	if dest_url.Scheme == "stash" {
		//return doWriteBack(source_url.path, dest_url.path, debug)
	}

	if dest_url.Scheme == "file" {
		destination = dest_url.Path
	}

	if source_url.Scheme == "stash" {
		sourceFile = source_url.Path
	}

	if string(sourceFile[0]) != "/" {
		sourceFile = "/" + sourceFile
	}

	payload := payloadStruct{}
	var found bool
	payload.sitename, found = os.LookupEnv("OSG_SITE_NAME")
	if !found {
		payload.sitename = "siteNotFound"
	}

	//Fill out the payload as much as possible
	payload.filename = source_url.Path

	// ??

	parse_job_ad(payload)

	payload.start1 = time.Now().Unix()

	// Go thru the download methods
	success := false

	// switch statement?
	for _, method := range methods {

		switch method {
		case "cvmfs":
			log.Info("Trying CVMFS...")
			if err := download_cvmfs(sourceFile, destination, &payload); err == nil {
				success = true
				break
				//check if break still works
			}
		case "xrootd":
			log.Info("Trying XROOTD...")
			if err := download_xrootd(sourceFile, destination, &payload); err == nil {
				success = true
				break
			}
		case "http":
			log.Info("Trying HTTP...")
			if err := download_http(sourceFile, destination, &payload); err == nil {
				success = true
				break
			}
		default:
			log.Errorf("Unknown transfer method: %s", method)
		}
	}

	payload.end1 = time.Now().Unix()

	payload.timestamp = payload.end1
	payload.downloadTime = (payload.end1 - payload.start1)

	if success {
		payload.status = "Success"

		// Get the final size of the download file

		info, err := os.Stat(destination)
		if err != nil {
			return err
		}
		payload.fileSize = info.Size()
		payload.downloadSize = payload.fileSize
	} else {
		log.Error("All methods failed! Unable to download file.")
		payload.status = "Fail"
	}

	// We really don't care if the es send fails, but log
	// it in debug if it does fail
	if err := es_send(&payload); err != nil {
		log.Debugln("Failed to send to data to ES")
		return nil
	} else {
		return nil
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

func get_ips(name string) []string {
	var ipv4s []string
	var ipv6s []string

	info, err := net.LookupHost(name)
	if err != nil {
		log.Error("Unable to look up %s", name)

		var empty []string
		return empty
	}

	for _, addr := range info {
		parsedIP := net.ParseIP(addr)

		if parsedIP.To4() != nil {
			ipv4s = append(ipv4s, addr)
		} else if parsedIP.To16() != nil {
			ipv6s = append(ipv6s, addr)
		}
	}

	//Randomize the order of each
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(ipv4s), func(i, j int) { ipv4s[i], ipv4s[j] = ipv4s[j], ipv4s[i] })
	rand.Shuffle(len(ipv6s), func(i, j int) { ipv6s[i], ipv6s[j] = ipv6s[j], ipv6s[i] })

	// Always prefer IPv4
	return append(ipv4s, ipv6s...)

}

func parse_job_ad(payload payloadStruct) { // TODO: needs the payload

	//Parse the .job.ad file for the Owner (username) and ProjectName of the callee.

	condorJobAd, isPresent := os.LookupEnv("_CONDOR_JOB_AD")
	var filename string
	if isPresent {
		filename = condorJobAd
	} else if _, err := os.Stat(".job.ad"); err == nil {
		filename = ".job.ad"
	} else {
		return
	}

	// https://stackoverflow.com/questions/28574609/how-to-apply-regexp-to-content-in-file-go

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	// Get all matches from file
	classadRegex, e := regexp.Compile(`^\s*(Owner|ProjectName)\s=\s"(.*)"`)
	if e != nil {
		log.Fatal(e)
	}

	matches := classadRegex.FindAll(b, -1)

	for _, match := range matches {
		if string(match[0]) == "Owner" {
			payload.Owner = string(match[1])
		} else if string(match) == "ProjectName" {
			payload.ProjectName = string(match[1])
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

func es_send(payload *payloadStruct) error {

	// calculate the current timestamp
	timeStamp := time.Now().Unix()
	payload.timestamp = timeStamp

	// convert payload to a JSON string (something with Marshall ...)
	var jsonBytes []byte
	var err error
	if jsonBytes, err = json.Marshal(payload); err != nil {
		log.Errorln("Failed to marshal payload JSON: ", err)
		return err
	}

	errorChan := make(chan error)

	go doEsSend(jsonBytes, errorChan)

	select {
	case returnedError := <-errorChan:
		return returnedError
	case <-time.After(5 * time.Second):
		log.Debugln("Send to ES timed out")
		return errors.New("ES send timed out")
	}

}

// Do the actual send to ES
// Should be called with a timeout
func doEsSend(jsonBytes []byte, errorChannel chan<- error) error {
	// Send a HTTP POST to collector.atlas-ml.org, with a timeout!
	resp, err := http.Post("http://collector.atlas-ml.org:9951", "application/json", bytes.NewBuffer(jsonBytes))

	if err != nil {
		log.Errorln("Can't get collector.atlas-ml.org:", err)
		errorChannel <- err
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	log.Debugln("Returned from collector.atlas-ml.org:", string(body))
	errorChannel <- nil
	return nil
}
