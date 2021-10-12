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

var (
    version = "dev"
    commit  = "none"
    date    = "unknown"
    builtBy = "unknown"
)


// Nearest cache
var nearest_cache string

// List of caches, in order from closest to furthest
var nearest_cache_list []string
var caches_json_location string


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
	Sources []string `positional-arg-name:"sources" short:"i" long:"input" description:"Source file(s)" default:"-"`

	// A useless variable.  It should alwasy be empty.  The Sources variable above should "grab" all of the positional arguments
	// The only reason we have this variable is so the help message has the [sources...] [destination] help mesage.
	Destination string `positional-arg-name:"destination" short:"o" long:"output" description:"Destination file/directory" default:"-"`
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
	Methods string `long:"methods" description:"Comma separated list of methods to try, in order." default:"cvmfs,xrootd,http"`

	// Token file to use for reading and/or writing
	Token string `long:"token" short:"t" description:"Token file to use for reading and/or writing"`

	ListCaches bool `long:"list-names" description:"Return the names of pre-configured cache lists and exit"`

	ListDir bool `long:"list-dir" short:"l" description:"List the directory pointed to by source"`

	// Version information
	Version bool `long:"version" short:"v" description:"Print the version and exit"`

	// Namespace information
	PrintNamespaces bool `long:"namespaces" description:"Print the namespace information and exit"`

	// List Types (xroot or xroots)
	ListType string `long:"cache-list-name" short:"n" description:"Cache list to use, currently either xroot or xroots" default:"xroot"`

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
		err := setLogging(log.DebugLevel)
		if err != nil {
			log.Panicln("Failed to set logging level to Debug:", err)
		}
	} else {
		err := setLogging(log.ErrorLevel)
		if err != nil {
			log.Panicln("Failed to set logging level to Error:", err)
		}

	}

	if options.Version {
		fmt.Println("Version:", version)
		fmt.Println("Build Date:", date)
		fmt.Println("Build Commit:", commit)
		fmt.Println("Built By:", builtBy)
		os.Exit(0)
	}

	if options.PrintNamespaces {
		namespaces, err := getNamespaces()
		if err != nil {
			fmt.Println("Failed to get namespaces:", err)
			os.Exit(1)
		}
		fmt.Printf("%+v\n", namespaces)
		os.Exit(0)
	}

	// Just return all the caches that it knows about
	// Print out all of the caches and exit
	if options.ListCaches {
		cacheList, err := get_best_stashcache(options.ListType)
		if err != nil {
			log.Errorln("Failed to get best caches:", err)
			os.Exit(1)
		}
		for _, cache := range cacheList {
			fmt.Print(cache)
		}
		fmt.Println()
		os.Exit(0)
	}

	if options.Closest {
		cacheList, err := get_best_stashcache(options.ListType)
		if err != nil {
			log.Errorln("Failed to get best stashcache: ", err)
		}
		fmt.Println(cacheList[0])
		os.Exit(0)
	}

	log.Debugln("Len of source:", len(options.SourceDestination.Sources))
	if len(options.SourceDestination.Sources) < 2 {
		log.Errorln("No Source or Destination")
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}
	source := options.SourceDestination.Sources[:len(options.SourceDestination.Sources)-1]
	dest := options.SourceDestination.Sources[len(options.SourceDestination.Sources)-1]

	log.Debugln("Sources:", source)
	log.Debugln("Destination:", dest)
	if options.ListDir {
		dirUrl, _ := url.Parse("http://stash.osgconnect.net:1094")
		dirUrl.Path = source[0]
		isDir, err := IsDir(dirUrl, "", Namespace{})
		if err != nil {
			log.Errorln("Error getting directory listing:", err)
		}
		log.Debugln("Dir is a directory?", isDir)
		return
	}

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

	// Convert the methods
	splitMethods := strings.Split(options.Methods, ",")

	if len(source) > 1 {
		if destStat, err := os.Stat(dest); err != nil && destStat.IsDir() {
			log.Errorln("Destination is not a directory")
			os.Exit(1)
		}
	}

	var result error
	for _, src := range source {
		result = doStashCPSingle(src, dest, splitMethods)
		if result != nil {
			break
		}
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		log.Errorln(GetErrors())
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

// Do writeback to stash using SciTokens
func doWriteBack(source string, destination *url.URL, namespace Namespace) error {

	scitoken_contents, err := getToken()
	if err != nil {
		return err
	}
	return UploadFile(source, destination, scitoken_contents, namespace)

}

func getToken() (string, error) {

	type tokenJson struct {
		AccessKey string `json:"access_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	/*
		Search for the location of the authentiction token.  It can be set explicitly on the command line (TODO),
		with the environment variable "TOKEN", or it can be searched in the standard HTCondor directory pointed
		to by the environment variable "_CONDOR_CREDS".
	*/
	var token_location string
	if options.Token != "" {
		token_location = options.Token
		log.Debugln("Getting token location from command line:", options.Token)
	} else {

		// https://golang.org/pkg/os/#LookupEnv
		tokenFile, isTokenSet := os.LookupEnv("TOKEN")
		credsDir, isCondorCredsSet := os.LookupEnv("_CONDOR_CREDS")

		// Backwards compatibility for getting scitokens
		// If TOKEN is not set in environment, and _CONDOR_CREDS is set, then...
		if isTokenSet {
			token_location = tokenFile
		} else if !isTokenSet && isCondorCredsSet {
			// Token wasn't specified on the command line or environment, try the default scitoken
			if _, err := os.Stat(filepath.Join(credsDir, "scitokens.use")); err == nil {
				token_location = filepath.Join(credsDir, "scitokens.use")
			}
		} else if _, err := os.Stat(".condor_creds/scitokens.use"); err == nil {
			token_location, _ = filepath.Abs(".condor_creds/scitokens.use")
		} else {
			// Print out, can't find token!  Print out error and exit with non-zero exit status
			// TODO: Better error message
			log.Errorln("Unable to find token file")
			return "", errors.New("failed to find token...")
		}
	}

	//Read in the JSON
	log.Debug("Opening token file: " + token_location)
	tokenContents, err := ioutil.ReadFile(token_location)
	if err != nil {
		log.Errorln("Error reading token file:", err)
		return "", err
	}
	tokenParsed := tokenJson{}
	if err := json.Unmarshal(tokenContents, &tokenParsed); err != nil {
		log.Debugln("Error unmarshalling JSON token contents:", err)
		log.Debugln("Assuming the token file is not JSON, and only contains the TOKEN")
		tokenStr := strings.TrimSpace(string(tokenContents))
		return tokenStr, nil
	}
	return tokenParsed.AccessKey, nil
}

// Start the transfer, whether read or write back
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

	// Get the namespace of the remote filesystem
	// For write back, it will be the destination
	// For read it will be the source.

	if dest_url.Scheme == "stash" {
		log.Debugln("Detected writeback")
		ns, err := MatchNamespace(dest_url.Path)
		if err != nil {
			log.Errorln("Failed to get namespace information:", err)
		}
		return doWriteBack(source_url.Path, dest_url, ns)
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

	ns, err := MatchNamespace(source_url.Path)
	if err != nil {
		return err
	}

	// get absolute path
	destPath, _ := filepath.Abs(destination)

	//Check if path exists or if its in a folder
	if destStat, err := os.Stat(destPath); os.IsNotExist(err) {
		destination = destPath
	} else if destStat.IsDir() {
		// Get the file name of the source
		sourceFilename := path.Base(sourceFile)
		destination = path.Join(destPath, sourceFilename)
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
Loop:
	for _, method := range methods {

		switch method {
		case "cvmfs":
			log.Info("Trying CVMFS...")
			if err := download_cvmfs(sourceFile, destination, &payload); err == nil {
				success = true
				break Loop
				//check if break still works
			}
		case "xrootd":
			log.Info("Trying XROOTD...")
			if err := download_xrootd(sourceFile, destination, &payload); err == nil {
				success = true
				break Loop
			}
		case "http":
			log.Info("Trying HTTP...")
			if err := download_http(sourceFile, destination, &payload, ns); err == nil {
				success = true
				break Loop
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
	}

	if !success {
		return errors.New("failed to download file")
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

// get_ips will resolve a hostname and return all corresponding IP addresses
// in DNS.  This can be used to randomly pick an IP when DNS round robin
// is used
func get_ips(name string) []string {
	var ipv4s []string
	var ipv6s []string

	info, err := net.LookupHost(name)
	if err != nil {
		log.Error("Unable to look up", name)

		var empty []string
		return empty
	}

	for _, addr := range info {
		parsedIP := net.ParseIP(addr)

		if parsedIP.To4() != nil {
			ipv4s = append(ipv4s, addr)
		} else if parsedIP.To16() != nil {
			ipv6s = append(ipv6s, "[" + addr + "]")
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

	// Need to make a closure in order to handle the error
	go func() {
		err := doEsSend(jsonBytes, errorChan)
		if err != nil {
			return
		}
	}()

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
	if err != nil {
		errorChannel <- err
		return err
	}
	log.Debugln("Returned from collector.atlas-ml.org:", string(body))
	errorChannel <- nil
	return nil
}
