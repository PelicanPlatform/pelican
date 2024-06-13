/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"math/rand"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/utils"
)

// Number of caches to attempt to use in any invocation
var CachesToTry int = 3

// Our own FileInfo structure to hold information about a file
// NOTE: this was created to provide more flexibility to information on a file. The fs.FileInfo interface was causing some issues like not always returning a Name attribute
// ALSO NOTE: the fields are exported so they can be marshalled into JSON, it does not work otherwise
type FileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
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

// getToken returns the token to use for the given destination
//
// If tokenName is not empty, it will be used as the token name.
// If tokenName is empty, the token name will be determined from the destination URL (if possible) using getTokenName
func getToken(destination *url.URL, namespace namespaces.Namespace, isWrite bool, tokenName string, tokenLocation string, acquireToken bool) (string, error) {
	if tokenName == "" {
		_, tokenName = getTokenName(destination)
	}

	type tokenJson struct {
		AccessKey string `json:"access_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	/*
		Search for the location of the authentiction token.  It can be set explicitly on the command line (TODO),
		with the environment variable "TOKEN", or it can be searched in the standard HTCondor directory pointed
		to by the environment variable "_CONDOR_CREDS".
	*/
	// WLCG Token Discovery
	if bearerToken, isBearerTokenSet := os.LookupEnv("BEARER_TOKEN"); tokenLocation == "" && isBearerTokenSet {
		return bearerToken, nil
	} else if bearerTokenFile, isBearerTokenFileSet := os.LookupEnv("BEARER_TOKEN_FILE"); tokenLocation == "" && isBearerTokenFileSet {
		if _, err := os.Stat(bearerTokenFile); err != nil {
			log.Warningln("Environment variable BEARER_TOKEN_FILE is set, but file being point to does not exist:", err)
		} else {
			tokenLocation = bearerTokenFile
		}
	}
	if xdgRuntimeDir, xdgRuntimeDirSet := os.LookupEnv("XDG_RUNTIME_DIR"); tokenLocation == "" && xdgRuntimeDirSet {
		// Get the uid
		uid := os.Getuid()
		tmpTokenPath := filepath.Join(xdgRuntimeDir, "bt_u"+strconv.Itoa(uid))
		if _, err := os.Stat(tmpTokenPath); err == nil {
			tokenLocation = tmpTokenPath
		}
	}

	// Check for /tmp/bt_u<uid>
	if tokenLocation == "" {
		uid := os.Getuid()
		tmpTokenPath := "/tmp/bt_u" + strconv.Itoa(uid)
		if _, err := os.Stat(tmpTokenPath); err == nil {
			tokenLocation = tmpTokenPath
		}
	}

	// Backwards compatibility for getting scitokens
	// If TOKEN is not set in environment, and _CONDOR_CREDS is set, then...
	if tokenFile, isTokenSet := os.LookupEnv("TOKEN"); isTokenSet && tokenLocation == "" {
		if _, err := os.Stat(tokenFile); err != nil {
			log.Warningln("Environment variable TOKEN is set, but file being point to does not exist:", err)
		} else {
			tokenLocation = tokenFile
		}
	}

	// Finally, look in the HTCondor runtime
	if tokenLocation == "" {
		tokenLocation = discoverHTCondorToken(tokenName)
	}

	if tokenLocation == "" {
		if acquireToken {
			opts := config.TokenGenerationOpts{Operation: config.TokenSharedRead}
			if isWrite {
				opts.Operation = config.TokenSharedWrite
			}
			value, err := AcquireToken(destination, namespace, opts)
			if err == nil {
				return value, nil
			}
			log.Errorln("Failed to generate a new authorization token for this transfer: ", err)
			log.Errorln("This transfer requires authorization to complete and no token is available")
			err = errors.New("failed to find or generate a token as required for " + destination.String())
			return "", err
		} else {
			log.Errorln("Credential is required, but currently missing")
			err := errors.New("Credential is required for " + destination.String() + " but is currently missing")
			return "", err
		}
	}

	//Read in the JSON
	log.Debug("Opening token file: " + tokenLocation)
	tokenContents, err := os.ReadFile(tokenLocation)
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

// Check the size of a remote file in an origin
func DoStat(ctx context.Context, destination string, options ...TransferOption) (fileInfo *FileInfo, err error) {

	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to stat:", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) while check file size: %v", r)
			err = errors.New(ret)
			return
		}
	}()

	destUri, err := url.Parse(destination)
	if err != nil {
		log.Errorln("Failed to parse destination URL")
		return nil, err
	}

	// Check if we understand the found url scheme
	err = schemeUnderstood(destUri.Scheme)
	if err != nil {
		return nil, err
	}

	te, err := NewTransferEngine(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()

	pelicanURL, err := te.newPelicanURL(destUri)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate pelicanURL object")
	}

	ns, err := getNamespaceInfo(ctx, destUri.Path, pelicanURL.directorUrl, false, "")
	if err != nil {
		return nil, err
	}

	tokenLocation := ""
	acquire := true
	token := ""
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionTokenLocation{}:
			tokenLocation = option.Value().(string)
		case identTransferOptionAcquireToken{}:
			acquire = option.Value().(bool)
		case identTransferOptionToken{}:
			token = option.Value().(string)
		}
	}

	if ns.UseTokenOnRead && token == "" {
		token, err = getToken(destUri, ns, true, "", tokenLocation, acquire)
		if err != nil {
			return nil, fmt.Errorf("failed to get token for transfer: %v", err)
		}
	}

	if statInfo, err := statHttp(ctx, destUri, ns, pelicanURL.directorUrl, token); err != nil {
		return nil, errors.Wrap(err, "failed to do the stat")
	} else {
		return &statInfo, nil
	}
}

func GetCacheHostnames(ctx context.Context, testFile string) (urls []string, err error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return
	}
	ns, err := getNamespaceInfo(ctx, testFile, fedInfo.DirectorEndpoint, false, "")
	if err != nil {
		return
	}

	caches, err := getCachesFromNamespace(ns, fedInfo.DirectorEndpoint != "", make([]*url.URL, 0))
	if err != nil {
		return
	}

	for _, cacheGeneric := range caches {
		if cache, ok := cacheGeneric.(namespaces.Cache); ok {
			url_string := cache.AuthEndpoint
			host := strings.Split(url_string, ":")[0]
			urls = append(urls, host)
		} else if cache, ok := cacheGeneric.(namespaces.DirectorCache); ok {
			cacheUrl, err := url.Parse(cache.EndpointUrl)
			if err != nil {
				log.Debugln("Failed to parse returned cache as a URL:", cacheUrl)
				continue
			}
			urls = append(urls, cacheUrl.Hostname())
		}
	}

	return
}

func getUserAgent(project string) (agent string) {
	agent = "pelican-client/" + config.GetVersion()
	if project != "" {
		agent += " project/" + project
	}
	return
}

func getCachesFromNamespace(namespace namespaces.Namespace, useDirector bool, preferredCaches []*url.URL) (caches []CacheInterface, err error) {
	var appendCaches bool
	// The global cache override is set
	if len(preferredCaches) > 0 {
		var preferredCacheList []CacheInterface
		for idx, preferredCache := range preferredCaches {
			cacheUrl := preferredCache.String()
			// If the preferred cache is empty, return an error
			if cacheUrl == "" {
				err = errors.New("Preferred cache was specified as an empty string")
				return
			} else if cacheUrl == "+" {
				// If we have a '+' in our list, the user wants to prepend the preferred caches to the "normal" list of caches
				// if the cache is a '+', verify it is at the end of our list, if not, return an error
				if idx != len(preferredCaches)-1 {
					err = errors.New("The special character '+' must be the last item in the list of preferred caches")
					return
				}
				// We want to signify that we want to append the "normal" cache list
				appendCaches = true
			} else {
				// We have a normal item in the preferred cache list
				log.Debugf("Using the cache (%s) from the config override\n", preferredCache)
				cache := namespaces.DirectorCache{
					EndpointUrl: cacheUrl,
				}
				// append to our list of preferred caches
				preferredCacheList = append(preferredCacheList, cache)
			}
		}

		// If we are not appending any more caches, we return with the caches we have
		if !appendCaches {
			caches = preferredCacheList
			return
		}
		caches = preferredCacheList
	}

	if useDirector {
		log.Debugln("Using the returned sources from the director")
		directorCaches := make([]CacheInterface, len(namespace.SortedDirectorCaches))
		for idx, val := range namespace.SortedDirectorCaches {
			directorCaches[idx] = val
		}

		// If appendCaches is set, prepend it to the list of caches and return
		if appendCaches {
			caches = append(caches, directorCaches...)
		} else {
			caches = directorCaches
		}
		if log.IsLevelEnabled(log.DebugLevel) || log.IsLevelEnabled(log.TraceLevel) {
			cacheHosts := make([]string, len(caches))
			for idx, entry := range caches {
				cacheStr := entry.(namespaces.DirectorCache).EndpointUrl
				cacheUrl, err := url.Parse(cacheStr)
				if err != nil {
					cacheHosts[idx] = cacheStr
				}
				cacheSimpleUrl := url.URL{
					Scheme: cacheUrl.Scheme,
					Host:   cacheUrl.Host,
				}
				cacheHosts[idx] = cacheSimpleUrl.String()
			}
			if len(cacheHosts) <= 6 {
				log.Debugln("Matched caches:", strings.Join(cacheHosts, ", "))
			} else {
				log.Debugf("Matched caches: %s ... (plus %d more)", strings.Join(cacheHosts[0:6], ", "), len(cacheHosts)-6)
				log.Traceln("matched caches continued:", cacheHosts[6:])
			}
		}
		return
	}

	var bestCaches []string
	if len(preferredCaches) == 0 {
		cacheListName := "xroot"
		if namespace.ReadHTTPS || namespace.UseTokenOnRead {
			cacheListName = "xroots"
		}
		bestCaches, err = GetBestCache(cacheListName)
		if err != nil {
			log.Errorln("Failed to get best caches:", err)
			return
		}
	}

	log.Debugln("Nearest cache list:", bestCaches)
	log.Debugln("Cache list name:", namespace.Caches)

	matchedCaches := namespace.MatchCaches(bestCaches)
	log.Debugln("Matched caches:", matchedCaches)
	matchedCachesList := make([]CacheInterface, len(matchedCaches))
	for idx, val := range matchedCaches {
		matchedCachesList[idx] = val
	}

	// If usingPreferredCache is set, prepend it to the list of caches and return
	if appendCaches {
		caches = append(caches, matchedCachesList...)
	} else {
		caches = matchedCachesList
	}

	return
}

func correctURLWithUnderscore(sourceFile string) (string, string) {
	schemeIndex := strings.Index(sourceFile, "://")
	if schemeIndex == -1 {
		return sourceFile, ""
	}

	originalScheme := sourceFile[:schemeIndex]
	if strings.Contains(originalScheme, "_") {
		scheme := strings.ReplaceAll(originalScheme, "_", ".")
		sourceFile = scheme + sourceFile[schemeIndex:]
	}
	return sourceFile, originalScheme
}

func discoverHTCondorToken(tokenName string) string {
	tokenLocation := ""

	// Tokens with dots in their name may need to have dots converted to underscores.
	if strings.Contains(tokenName, ".") {
		underscoreTokenName := strings.ReplaceAll(tokenName, ".", "_")
		// If we find a token after replacing dots, then we're already done.
		tokenLocation = discoverHTCondorToken(underscoreTokenName)
		if tokenLocation != "" {
			return tokenLocation
		}
	}

	tokenFilename := "scitokens.use"
	if len(tokenName) > 0 {
		tokenFilename = tokenName + ".use"
	}
	log.Debugln("Looking for token file:", tokenFilename)
	if credsDir, isCondorCredsSet := os.LookupEnv("_CONDOR_CREDS"); tokenLocation == "" && isCondorCredsSet {
		// Token wasn't specified on the command line or environment, try the default scitoken
		if _, err := os.Stat(filepath.Join(credsDir, tokenFilename)); err != nil {
			log.Warningln("Environment variable _CONDOR_CREDS is set, but file being point to does not exist:", err)
		} else {
			tokenLocation = filepath.Join(credsDir, tokenFilename)
		}
	}
	if _, err := os.Stat(".condor_creds/" + tokenFilename); err == nil && tokenLocation == "" {
		tokenLocation, _ = filepath.Abs(".condor_creds/" + tokenFilename)
	}
	return tokenLocation
}

// Retrieve federation namespace information for a given URL.
// If OSDFDirectorUrl is non-empty, then the namespace information will be pulled from the director;
// otherwise, it is pulled from topology.
func getNamespaceInfo(ctx context.Context, resourcePath, OSDFDirectorUrl string, isPut bool, query string) (ns namespaces.Namespace, err error) {
	// If we have a director set, go through that for namespace info, otherwise use topology
	if OSDFDirectorUrl != "" {
		log.Debugln("Will query director at", OSDFDirectorUrl, "for object", resourcePath)
		verb := "GET"
		if isPut {
			verb = "PUT"
		}
		if query != "" {
			resourcePath += "?" + query
		}
		var dirResp *http.Response
		dirResp, err = queryDirector(ctx, verb, resourcePath, OSDFDirectorUrl)
		if err != nil {
			if isPut && dirResp != nil && dirResp.StatusCode == 405 {
				err = errors.New("Error 405: No writeable origins were found")
				return
			} else {
				log.Errorln("Error while querying the Director:", err)
				return
			}
		}
		ns, err = CreateNsFromDirectorResp(dirResp)
		if err != nil {
			return
		}

		// if we are doing a PUT, we need to get our endpoint from the director
		if isPut {
			var writeBackUrl *url.URL
			location := dirResp.Header.Get("Location")
			writeBackUrl, err = url.Parse(location)
			if err != nil {
				log.Errorf("The director responded with an invalid location (does not parse as URL: %v): %s", err, location)
				return
			}
			ns.WriteBackHost = "https://" + writeBackUrl.Host
		}
		return
	} else {
		log.Debugln("Director URL not found, searching in topology")
		ns, err = namespaces.MatchNamespace(ctx, resourcePath)
		if err != nil {
			return
		}
		return
	}
}

func schemeUnderstood(scheme string) error {
	understoodSchemes := []string{"file", "osdf", "pelican", "stash", ""}

	_, foundDest := find(understoodSchemes, scheme)
	if !foundDest {
		return errors.Errorf("Do not understand the destination scheme: %s. Permitted values are %s",
			scheme, strings.Join(understoodSchemes, ", "))
	}
	return nil
}

// Function for the object ls command, we get target information for our remote object and eventually print out the contents of the specified object
func DoList(ctx context.Context, remoteObject string, options ...TransferOption) (fileInfos []FileInfo, err error) {
	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform transfer (DoList):", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in DoList: %v", r)
			err = errors.New(ret)
		}
	}()

	remoteObjectUrl, err := url.Parse(remoteObject)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse remote object URL")
	}

	remoteObjectScheme := remoteObjectUrl.Scheme

	// Check if we understand the found url scheme
	err = schemeUnderstood(remoteObjectScheme)
	if err != nil {
		return nil, err
	}
	te, err := NewTransferEngine(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()

	pelicanURL, err := te.newPelicanURL(remoteObjectUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate pelicanURL object")
	}

	ns, err := getNamespaceInfo(ctx, remoteObjectUrl.Path, pelicanURL.directorUrl, false, "")
	if err != nil {
		return nil, err
	}

	// Get our token if needed
	tokenLocation := ""
	acquire := true
	token := ""
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionTokenLocation{}:
			tokenLocation = option.Value().(string)
		case identTransferOptionAcquireToken{}:
			acquire = option.Value().(bool)
		case identTransferOptionToken{}:
			token = option.Value().(string)
		}
	}

	if ns.UseTokenOnRead && token == "" {
		token, err = getToken(remoteObjectUrl, ns, true, "", tokenLocation, acquire)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get token for transfer")
		}
	}

	fileInfos, err = listHttp(ctx, remoteObjectUrl, pelicanURL.directorUrl, ns, token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to do the list")
	}

	return fileInfos, nil
}

/*
	Start of transfer for pelican object put, gets information from the target destination before doing our HTTP PUT request

localObject: the source file/directory you would like to upload
remoteDestination: the end location of the upload
recursive: a boolean indicating if the source is a directory or not
*/
func DoPut(ctx context.Context, localObject string, remoteDestination string, recursive bool, options ...TransferOption) (transferResults []TransferResults, err error) {
	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform transfer (DoPut):", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in DoPut: %v", r)
			err = errors.New(ret)
		}
	}()

	remoteDestination, remoteDestScheme := correctURLWithUnderscore(remoteDestination)
	remoteDestUrl, err := url.Parse(remoteDestination)
	if err != nil {
		log.Errorln("Failed to parse remote destination URL:", err)
		return nil, err
	}

	// Check if we have a query and that it is understood
	err = utils.CheckValidQuery(remoteDestUrl)
	if err != nil {
		return
	}
	if remoteDestUrl.Query().Has("recursive") {
		recursive = true
	}

	remoteDestUrl.Scheme = remoteDestScheme

	remoteDestScheme, _ = getTokenName(remoteDestUrl)

	// Check if we understand the found url scheme
	err = schemeUnderstood(remoteDestScheme)
	if err != nil {
		return nil, err
	}

	te, err := NewTransferEngine(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()
	client, err := te.NewClient(options...)
	if err != nil {
		return
	}
	tj, err := client.NewTransferJob(context.Background(), remoteDestUrl, localObject, true, recursive)
	if err != nil {
		return
	}
	if err = client.Submit(tj); err != nil {
		return
	}
	transferResults, err = client.Shutdown()
	if tj.lookupErr != nil {
		err = tj.lookupErr
	}
	for _, result := range transferResults {
		if err == nil && result.Error != nil {
			err = result.Error
		}
	}
	return
}

/*
	Start of transfer for pelican object get, gets information from the target source before doing our HTTP GET request

remoteObject: the source file/directory you would like to upload
localDestination: the end location of the upload
recursive: a boolean indicating if the source is a directory or not
*/
func DoGet(ctx context.Context, remoteObject string, localDestination string, recursive bool, options ...TransferOption) (transferResults []TransferResults, err error) {
	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform transfer (DoGet):", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in DoGet: %v", r)
			err = errors.New(ret)
		}
	}()

	// Parse the source with URL parse
	remoteObject, remoteObjectScheme := correctURLWithUnderscore(remoteObject)
	remoteObjectUrl, err := url.Parse(remoteObject)
	if err != nil {
		log.Errorln("Failed to parse source URL:", err)
		return nil, err
	}

	// Check if we have a query and that it is understood
	err = utils.CheckValidQuery(remoteObjectUrl)
	if err != nil {
		return
	}
	if remoteObjectUrl.Query().Has("recursive") {
		recursive = true
	}

	remoteObjectUrl.Scheme = remoteObjectScheme

	// This is for condor cases:
	remoteObjectScheme, _ = getTokenName(remoteObjectUrl)

	// Check if we understand the found url scheme
	err = schemeUnderstood(remoteObjectScheme)
	if err != nil {
		return nil, err
	}

	if remoteObjectScheme == "osdf" || remoteObjectScheme == "pelican" {
		remoteObject = remoteObjectUrl.Path
	}

	if string(remoteObject[0]) != "/" {
		remoteObject = "/" + remoteObject
	}

	// get absolute path
	localDestPath, _ := filepath.Abs(localDestination)

	//Check if path exists or if its in a folder
	if destStat, err := os.Stat(localDestPath); os.IsNotExist(err) {
		localDestination = localDestPath
	} else if destStat.IsDir() && remoteObjectUrl.Query().Get("pack") == "" {
		// If we have an auto-pack request, it's OK for the destination to be a directory
		// Otherwise, get the base name of the source and append it to the destination dir.
		remoteObjectFilename := path.Base(remoteObject)
		localDestination = path.Join(localDestPath, remoteObjectFilename)
	}

	success := false

	te, err := NewTransferEngine(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()
	tc, err := te.NewClient(options...)
	if err != nil {
		return
	}
	tj, err := tc.NewTransferJob(context.Background(), remoteObjectUrl, localDestination, false, recursive)
	if err != nil {
		return
	}
	err = tc.Submit(tj)
	if err != nil {
		return
	}

	transferResults, err = tc.Shutdown()
	if err == nil {
		if tj.lookupErr == nil {
			success = true
		} else {
			err = tj.lookupErr
		}
	}
	var downloaded int64 = 0
	for _, result := range transferResults {
		downloaded += result.TransferredBytes
		if err == nil && result.Error != nil {
			success = false
			err = result.Error
		}
	}

	if success {
		// Get the final size of the download file
	} else {
		log.Error("Http GET failed! Unable to download file:", err)
	}

	if !success {
		// If there's only a single transfer error, remove the wrapping to provide
		// a simpler error message.  Results in:
		//    failed download from local-cache: server returned 404 Not Found
		// versus:
		//    failed to download file: transfer error: failed download from local-cache: server returned 404 Not Found
		var te *TransferErrors
		if errors.As(err, &te) {
			if len(te.Unwrap()) == 1 {
				var tae *TransferAttemptError
				if errors.As(te.Unwrap()[0], &tae) {
					return nil, tae
				} else {
					return nil, errors.Wrap(err, "failed to download file")
				}
			}
			return nil, te
		}
		return nil, errors.Wrap(err, "failed to download file")
	} else {
		return transferResults, err
	}
}

// Start the transfer, whether read or write back. Primarily used for backwards compatibility
func DoCopy(ctx context.Context, sourceFile string, destination string, recursive bool, options ...TransferOption) (transferResults []TransferResults, err error) {

	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform transfer (DoStashCPSingle):", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in DoStashCPSingle: %v", r)
			err = errors.New(ret)
		}
	}()

	// Parse the source and destination with URL parse
	sourceFile, source_scheme := correctURLWithUnderscore(sourceFile)
	sourceURL, err := url.Parse(sourceFile)
	if err != nil {
		log.Errorln("Failed to parse source URL:", err)
		return nil, err
	}
	// Check if we have a query and that it is understood
	err = utils.CheckValidQuery(sourceURL)
	if err != nil {
		return
	}
	if sourceURL.Query().Has("recursive") {
		recursive = true
	}

	sourceURL.Scheme = source_scheme

	destination, dest_scheme := correctURLWithUnderscore(destination)
	destURL, err := url.Parse(destination)
	if err != nil {
		log.Errorln("Failed to parse destination URL:", err)
		return nil, err
	}

	// Check if we have a query and that it is understood
	err = utils.CheckValidQuery(destURL)
	if err != nil {
		return
	}
	if destURL.Query().Has("recursive") {
		recursive = true
	}

	destURL.Scheme = dest_scheme

	// Check for scheme here for when using condor
	sourceScheme, _ := getTokenName(sourceURL)
	destScheme, _ := getTokenName(destURL)

	isPut := destScheme == "stash" || destScheme == "osdf" || destScheme == "pelican"

	var localPath string
	var remoteURL *url.URL
	if isPut {
		// Verify valid scheme
		if err = schemeUnderstood(destScheme); err != nil {
			return nil, err
		}

		log.Debugln("Detected object write to remote federation object", destURL.Path)
		localPath = sourceFile
		remoteURL = destURL
	} else {
		// Verify valid scheme
		if err = schemeUnderstood(sourceScheme); err != nil {
			return nil, err
		}

		if destURL.Scheme == "file" {
			destination = destURL.Path
		}

		if sourceScheme == "stash" || sourceScheme == "osdf" || sourceScheme == "pelican" {
			sourceFile = sourceURL.Path
		}

		if string(sourceFile[0]) != "/" {
			sourceFile = "/" + sourceFile
		}

		// get absolute path
		destPath, _ := filepath.Abs(destination)

		//Check if path exists or if its in a folder
		if destStat, err := os.Stat(destPath); os.IsNotExist(err) {
			destination = destPath
		} else if destStat.IsDir() && sourceURL.Query().Get("pack") == "" {
			// If we have an auto-pack request, it's OK for the destination to be a directory
			// Otherwise, get the base name of the source and append it to the destination dir.
			sourceFilename := path.Base(sourceFile)
			destination = path.Join(destPath, sourceFilename)
		}
		localPath = destination
		remoteURL = sourceURL
	}

	success := false
	var downloaded int64 = 0

	te, err := NewTransferEngine(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()
	tc, err := te.NewClient(options...)
	if err != nil {
		return
	}
	tj, err := tc.NewTransferJob(context.Background(), remoteURL, localPath, isPut, recursive)
	if err != nil {
		return
	}
	if err = tc.Submit(tj); err != nil {
		return
	}
	transferResults, err = tc.Shutdown()
	if err == nil {
		if tj.lookupErr == nil {
			success = true
		} else {
			err = tj.lookupErr
		}
	}

	for _, result := range transferResults {
		downloaded += result.TransferredBytes
		if err == nil && result.Error != nil {
			success = false
			err = result.Error
		}
	}

	if success {
		return transferResults, nil
	} else {
		return transferResults, err
	}
}

// find takes a slice and looks for an element in it. If found it will
// return it's key, otherwise it will return -1 and a bool of false.
// From https://golangcode.com/check-if-element-exists-in-slice/
func find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

// getIPs will resolve a hostname and return all corresponding IP addresses
// in DNS.  This can be used to randomly pick an IP when DNS round robin
// is used
func getIPs(name string) []string {
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
	rand.Shuffle(len(ipv4s), func(i, j int) { ipv4s[i], ipv4s[j] = ipv4s[j], ipv4s[i] })
	rand.Shuffle(len(ipv6s), func(i, j int) { ipv6s[i], ipv6s[j] = ipv6s[j], ipv6s[i] })

	// Always prefer IPv4
	return append(ipv4s, ipv6s...)

}
