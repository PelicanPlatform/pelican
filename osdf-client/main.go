package stashcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
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

	log "github.com/sirupsen/logrus"
)

type OptionsStruct struct {
	ProgressBars bool
	Recursive    bool
	Token        string
	Version      string
}

var Options OptionsStruct

var (
	version string
)

// Nearest cache
var NearestCache string

// List of caches, in order from closest to furthest
var NearestCacheList []string
var CachesJsonLocation string

// Number of caches to attempt to use in any invocation
var CachesToTry int = 3

// CacheOverride
var CacheOverride bool

type payloadStruct struct {
	filename     string
	sitename     string
	status       string
	Owner        string
	ProjectName  string
	version      string
	start1       int64
	end1         int64
	timestamp    int64
	downloadTime int64
	fileSize     int64
	downloadSize int64
}

// Determine the token name if it is embedded in the scheme, Condor-style
func getTokenName(destination *url.URL) (scheme, tokenName string) {
	schemePieces := strings.Split(destination.Scheme, "+")
	tokenName = ""
	// Scheme is always the last piece
	scheme = schemePieces[len(schemePieces)-1]
	// If there are 2 or more pieces, token name is everything but the last item, joined with a +
	if len(schemePieces) > 1 {
		tokenName = strings.Join(schemePieces[:len(schemePieces)-1], "+")
	}
	return
}

// Do writeback to stash using SciTokens
func doWriteBack(source string, destination *url.URL, namespace Namespace) (int64, error) {

	scitoken_contents, err := getToken(destination, namespace, true)
	if err != nil {
		return 0, err
	}
	return UploadFile(source, destination, scitoken_contents, namespace)

}

func getToken(destination *url.URL, namespace Namespace, isWrite bool) (string, error) {
	_, token_name := getTokenName(destination)

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
	if Options.Token != "" {
		token_location = Options.Token
		log.Debugln("Getting token location from command line:", Options.Token)
	} else {

		// WLCG Token Discovery
		if bearerToken, isBearerTokenSet := os.LookupEnv("BEARER_TOKEN"); isBearerTokenSet {
			return bearerToken, nil
		} else if bearerTokenFile, isBearerTokenFileSet := os.LookupEnv("BEARER_TOKEN_FILE"); isBearerTokenFileSet {
			if _, err := os.Stat(bearerTokenFile); err != nil {
				log.Warningln("Environment variable BEARER_TOKEN_FILE is set, but file being point to does not exist:", err)
			} else {
				token_location = bearerTokenFile
			}
		}
		if xdgRuntimeDir, xdgRuntimeDirSet := os.LookupEnv("XDG_RUNTIME_DIR"); token_location == "" && xdgRuntimeDirSet {
			// Get the uid
			uid := os.Getuid()
			tmpTokenPath := filepath.Join(xdgRuntimeDir, "bt_u"+strconv.Itoa(uid))
			if _, err := os.Stat(tmpTokenPath); err == nil {
				token_location = tmpTokenPath
			}
		}

		// Check for /tmp/bt_u<uid>
		if token_location == "" {
			uid := os.Getuid()
			tmpTokenPath := "/tmp/bt_u" + strconv.Itoa(uid)
			if _, err := os.Stat(tmpTokenPath); err == nil {
				token_location = tmpTokenPath
			}
		}

		// Backwards compatibility for getting scitokens
		// If TOKEN is not set in environment, and _CONDOR_CREDS is set, then...
		if tokenFile, isTokenSet := os.LookupEnv("TOKEN"); isTokenSet && token_location == "" {
			if _, err := os.Stat(tokenFile); err != nil {
				log.Warningln("Environment variable TOKEN is set, but file being point to does not exist:", err)
			} else {
				token_location = tokenFile
			}
		}

		// Finally, look in the HTCondor runtime
		token_filename := "scitokens.use"
		if len(token_name) > 0 {
			token_filename = token_name + ".use"
		}
		if credsDir, isCondorCredsSet := os.LookupEnv("_CONDOR_CREDS"); token_location == "" && isCondorCredsSet {
			// Token wasn't specified on the command line or environment, try the default scitoken
			if _, err := os.Stat(filepath.Join(credsDir, token_filename)); err != nil {
				log.Warningln("Environment variable _CONDOR_CREDS is set, but file being point to does not exist:", err)
			} else {
				token_location = filepath.Join(credsDir, token_filename)
			}
		}
		if _, err := os.Stat(".condor_creds/" + token_filename); err == nil && token_location == "" {
			token_location, _ = filepath.Abs(".condor_creds/" + token_filename)
		}
		if token_location == "" {
			value, err := AcquireToken(destination, namespace, isWrite)
			if err == nil {
				return value, nil
			}
			log.Errorln("Failed to generate a new authorization token for this transfer: ", err)
			log.Errorln("This transfer requires authorization to complete and no token is available")
			err = errors.New("failed to find or generate a token as required for " + destination.String())
			AddError(err)
			return "", err
		}
	}

	//Read in the JSON
	log.Debug("Opening token file: " + token_location)
	tokenContents, err := os.ReadFile(token_location)
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

func GetCacheHostnames(testFile string) (urls []string, err error) {

	ns, err := MatchNamespace(testFile)
	if err != nil {
		return
	}

	caches, err := GetCachesFromNamespace(ns)
	if err != nil {
		return
	}

	for _, cache := range caches {
		url_string := cache.AuthEndpoint
		host := strings.Split(url_string, ":")[0]
		urls = append(urls, host)
	}

	return
}

func GetCachesFromNamespace(namespace Namespace) (caches []Cache, err error) {

	cacheListName := "xroot"
	if namespace.ReadHTTPS || namespace.UseTokenOnRead {
		cacheListName = "xroots"
	}
	if len(NearestCacheList) == 0 {
		_, err = GetBestCache(cacheListName)
		if err != nil {
			log.Errorln("Failed to get best caches:", err)
			return
		}
	}

	log.Debugln("Nearest cache list:", NearestCacheList)
	log.Debugln("Cache list name:", namespace.Caches)

	// The main routine can set a global cache to use
	if CacheOverride {
		cache := Cache{
			Endpoint:     NearestCache,
			AuthEndpoint: NearestCache,
			Resource:     NearestCache,
		}
		caches = []Cache{cache}
	} else {
		caches = namespace.MatchCaches(NearestCacheList)
	}
	log.Debugln("Matched caches:", caches)

	return
}

// Start the transfer, whether read or write back
func DoStashCPSingle(sourceFile string, destination string, methods []string, recursive bool) (bytesTransferred int64, err error) {

	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic captured while attempting to perform transfer (DoStashCPSingle):", r)
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in DoStashCPSingle: %v", r)
			err = errors.New(ret)
			bytesTransferred = 0

			// Attempt to add the panic to the error accumulator
			AddError(errors.New(ret))
		}
	}()

	// Parse the source and destination with URL parse

	source_url, err := url.Parse(sourceFile)
	if err != nil {
		log.Errorln("Failed to parse source URL:", err)
		return 0, err
	}

	dest_url, err := url.Parse(destination)
	if err != nil {
		log.Errorln("Failed to parse destination URL:", err)
		return 0, err
	}

	// If there is a host specified, prepend it to the path
	if source_url.Host != "" {
		source_url.Path = path.Join(source_url.Host, source_url.Path)
	}

	if dest_url.Host != "" {
		dest_url.Path = path.Join(dest_url.Host, dest_url.Path)
	}

	sourceScheme, _ := getTokenName(source_url)
	destScheme, _ := getTokenName(dest_url)

	understoodSchemes := []string{"stash", "file", "osdf", ""}

	_, foundSource := Find(understoodSchemes, sourceScheme)
	if !foundSource {
		log.Errorln("Do not understand source scheme:", source_url.Scheme)
		return 0, errors.New("Do not understand source scheme")
	}

	_, foundDest := Find(understoodSchemes, destScheme)
	if !foundDest {
		log.Errorln("Do not understand destination scheme:", source_url.Scheme)
		return 0, errors.New("Do not understand destination scheme")
	}

	// Get the namespace of the remote filesystem
	// For write back, it will be the destination
	// For read it will be the source.

	if destScheme == "stash" || destScheme == "osdf" {
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

	if sourceScheme == "stash" || sourceScheme == "osdf" {
		sourceFile = source_url.Path
	}

	if string(sourceFile[0]) != "/" {
		sourceFile = "/" + sourceFile
	}

	OSDFDirectorUrl, useOSDFDirector := os.LookupEnv("OSDF_DIRECTOR_URL")

	var ns Namespace
	if useOSDFDirector {
		dirResp, err := QueryDirector(sourceFile, OSDFDirectorUrl)
		if err != nil {
			log.Errorln("Error while querying the Director:", err)
			return 0, err
		}
		err = CreateNsFromDirectorResp(dirResp, &ns)
		if err != nil {
			log.Errorln("Error parsing namespace information from Director:", err)
			return 0, err
		}
	} else {
		ns, err = MatchNamespace(source_url.Path)
		if err != nil {
			log.Errorln("Error matching namespace:", err)
			return 0, err
		}
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
	payload.version = version
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

	// If recursive, only do http method to guarantee freshest directory contents
	if Options.Recursive {
		methods = []string{"http"}
	}

	_, token_name := getTokenName(source_url)

	// switch statement?
	var downloaded int64 = 0
Loop:
	for _, method := range methods {

		switch method {
		case "cvmfs":
			if strings.HasPrefix(sourceFile, "/osgconnect/") {
				log.Info("Trying CVMFS...")
				if downloaded, err = download_cvmfs(sourceFile, destination, &payload); err == nil {
					success = true
					break Loop
					//check if break still works
				}
			} else {
				log.Debug("Skipping CVMFS as file does not start with /osgconnect/")
			}
		case "http":
			log.Info("Trying HTTP...")
			if downloaded, err = download_http(sourceFile, destination, &payload, ns, recursive, token_name, OSDFDirectorUrl); err == nil {
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
		payload.fileSize = downloaded
		payload.downloadSize = downloaded
	} else {
		log.Error("All methods failed! Unable to download file.")
		payload.status = "Fail"
	}

	if !success {
		return downloaded, errors.New("failed to download file")
	} else {
		return downloaded, nil
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
			ipv6s = append(ipv6s, "["+addr+"]")
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

	b, err := os.ReadFile(filename)
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
