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
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"

	"math/rand"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
)

type (
	payloadStruct struct {
		filename     string
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
)

// Number of caches to attempt to use in any invocation
var CachesToTry int = 3

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
			log.Errorln("Credential is required, but currently mssing")
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
func DoStat(ctx context.Context, destination string, options ...TransferOption) (remoteSize uint64, err error) {

	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform size check:", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) while check file size: %v", r)
			err = errors.New(ret)
			remoteSize = 0
		}
	}()

	dest_uri, err := url.Parse(destination)
	if err != nil {
		log.Errorln("Failed to parse destination URL")
		return 0, err
	}

	understoodSchemes := []string{"osdf", "pelican", ""}

	_, foundSource := Find(understoodSchemes, dest_uri.Scheme)
	if !foundSource {
		log.Errorln("Unknown schema provided:", dest_uri.Scheme)
		return 0, errors.New("Unsupported scheme requested")
	}

	origScheme := dest_uri.Scheme
	if config.GetPreferredPrefix() != "PELICAN" && origScheme == "" {
		dest_uri.Scheme = "osdf"
	}
	if (dest_uri.Scheme == "osdf" || dest_uri.Scheme == "stash") && dest_uri.Host != "" {
		dest_uri.Path = path.Clean("/" + dest_uri.Host + "/" + dest_uri.Path)
		dest_uri.Host = ""
	} else if dest_uri.Scheme == "pelican" {
		federationUrl, _ := url.Parse(dest_uri.String())
		federationUrl.Scheme = "https"
		federationUrl.Path = ""
		viper.Set("Federation.DiscoveryUrl", federationUrl.String())
		err = config.DiscoverFederation()
		if err != nil {
			return 0, err
		}
	}

	ns, err := namespaces.MatchNamespace(dest_uri.Path)
	if err != nil {
		return 0, err
	}

	tokenLocation := ""
	acquire := true
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionTokenLocation{}:
			tokenLocation = option.Value().(string)
		case identTransferOptionAcquireToken{}:
			acquire = option.Value().(bool)
		}
	}

	if remoteSize, err = statHttp(ctx, dest_uri, ns, tokenLocation, acquire); err == nil {
		return remoteSize, nil
	}
	return 0, err
}

func GetCacheHostnames(testFile string) (urls []string, err error) {

	directorUrl := param.Federation_DirectorUrl.GetString()
	ns, err := getNamespaceInfo(testFile, directorUrl, false)
	if err != nil {
		return
	}

	caches, err := getCachesFromNamespace(ns, directorUrl != "", make([]*url.URL, 0))
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

	// The global cache override is set
	if len(preferredCaches) > 0 {
		if preferredCaches[0].String() == "" {
			err = errors.New("Preferred cache was specified as an empty string")
			return
		}
		log.Debugf("Using the cache (%s) from the config override\n", preferredCaches[0])
		cache := namespaces.DirectorCache{
			EndpointUrl: preferredCaches[0].String(),
		}
		caches = []CacheInterface{cache}
		return
	}

	if useDirector {
		log.Debugln("Using the returned sources from the director")
		caches = make([]CacheInterface, len(namespace.SortedDirectorCaches))
		for idx, val := range namespace.SortedDirectorCaches {
			caches[idx] = val
		}
		log.Debugln("Matched caches:", caches)
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
	caches = make([]CacheInterface, len(matchedCaches))
	for idx, val := range matchedCaches {
		caches[idx] = val
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
func getNamespaceInfo(resourcePath, OSDFDirectorUrl string, isPut bool) (ns namespaces.Namespace, err error) {
	// If we have a director set, go through that for namespace info, otherwise use topology
	if OSDFDirectorUrl != "" {
		log.Debugln("Will query director at", OSDFDirectorUrl, "for object", resourcePath)
		verb := "GET"
		if isPut {
			verb = "PUT"
		}
		var dirResp *http.Response
		dirResp, err = queryDirector(verb, resourcePath, OSDFDirectorUrl)
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
		ns, err = namespaces.MatchNamespace(resourcePath)
		if err != nil {
			return
		}
		return
	}
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
	remoteDestUrl.Scheme = remoteDestScheme
	fd := config.GetFederation()
	defer config.SetFederation(fd)

	if remoteDestUrl.Host != "" {
		if remoteDestUrl.Scheme == "osdf" || remoteDestUrl.Scheme == "stash" {
			remoteDestUrl.Path, err = url.JoinPath(remoteDestUrl.Host, remoteDestUrl.Path)
			if err != nil {
				log.Errorln("Failed to join remote destination url path:", err)
				return nil, err
			}
		} else if remoteDestUrl.Scheme == "pelican" {

			config.SetFederation(config.FederationDiscovery{})
			federationUrl, _ := url.Parse(remoteDestUrl.String())
			federationUrl.Scheme = "https"
			federationUrl.Path = ""
			viper.Set("Federation.DiscoveryUrl", federationUrl.String())
			err = config.DiscoverFederation()
			if err != nil {
				return nil, err
			}
		}
	}
	remoteDestScheme, _ = getTokenName(remoteDestUrl)

	understoodSchemes := []string{"file", "osdf", "pelican", ""}

	_, foundDest := Find(understoodSchemes, remoteDestScheme)
	if !foundDest {
		return nil, fmt.Errorf("Do not understand the destination scheme: %s. Permitted values are %s",
			remoteDestUrl.Scheme, strings.Join(understoodSchemes, ", "))
	}

	te := NewTransferEngine(ctx)
	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()
	client, err := te.NewClient(options...)
	if err != nil {
		return
	}
	tj, err := client.NewTransferJob(remoteDestUrl, localObject, true, recursive)
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
	remoteObjectUrl.Scheme = remoteObjectScheme
	fd := config.GetFederation()
	defer config.SetFederation(fd)

	// If there is a host specified, prepend it to the path in the osdf case
	if remoteObjectUrl.Host != "" {
		if remoteObjectUrl.Scheme == "osdf" {
			remoteObjectUrl.Path, err = url.JoinPath(remoteObjectUrl.Host, remoteObjectUrl.Path)
			if err != nil {
				log.Errorln("Failed to join source url path:", err)
				return nil, err
			}
		} else if remoteObjectUrl.Scheme == "pelican" {

			config.SetFederation(config.FederationDiscovery{})
			federationUrl, _ := url.Parse(remoteObjectUrl.String())
			federationUrl.Scheme = "https"
			federationUrl.Path = ""
			viper.Set("Federation.DiscoveryUrl", federationUrl.String())
			err = config.DiscoverFederation()
			if err != nil {
				return nil, err
			}
		}
	}

	remoteObjectScheme, _ = getTokenName(remoteObjectUrl)

	understoodSchemes := []string{"file", "osdf", "pelican", ""}

	_, foundSource := Find(understoodSchemes, remoteObjectScheme)
	if !foundSource {
		return nil, fmt.Errorf("Do not understand the source scheme: %s. Permitted values are %s",
			remoteObjectUrl.Scheme, strings.Join(understoodSchemes, ", "))
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

	payload := payloadStruct{}
	payload.version = config.GetVersion()

	//Fill out the payload as much as possible
	payload.filename = remoteObjectUrl.Path

	parseJobAd(&payload)

	start := time.Now()
	payload.start1 = start.Unix()

	success := false

	te := NewTransferEngine(ctx)
	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()
	tc, err := te.NewClient(options...)
	if err != nil {
		return
	}
	tj, err := tc.NewTransferJob(remoteObjectUrl, localDestination, false, recursive)
	if err != nil {
		return
	}
	err = tc.Submit(tj)
	if err != nil {
		return
	}

	transferResults, err = tc.Shutdown()
	end := time.Now()
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
	}

	payload.end1 = end.Unix()

	payload.timestamp = payload.end1
	payload.downloadTime = int64(end.Sub(start).Seconds())

	if success {
		payload.status = "Success"

		// Get the final size of the download file
		payload.fileSize = downloaded
		payload.downloadSize = downloaded
	} else {
		log.Error("Http GET failed! Unable to download file:", err)
		payload.status = "Fail"
	}

	if !success {
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
	sourceURL.Scheme = source_scheme

	destination, dest_scheme := correctURLWithUnderscore(destination)
	dest_url, err := url.Parse(destination)
	if err != nil {
		log.Errorln("Failed to parse destination URL:", err)
		return nil, err
	}
	dest_url.Scheme = dest_scheme
	fd := config.GetFederation()
	defer config.SetFederation(fd)

	// If there is a host specified, prepend it to the path in the osdf case
	if sourceURL.Host != "" {
		if sourceURL.Scheme == "osdf" || sourceURL.Scheme == "stash" {
			sourceURL.Path = "/" + path.Join(sourceURL.Host, sourceURL.Path)
		} else if sourceURL.Scheme == "pelican" {
			config.SetFederation(config.FederationDiscovery{})
			federationUrl, _ := url.Parse(sourceURL.String())
			federationUrl.Scheme = "https"
			federationUrl.Path = ""
			viper.Set("Federation.DiscoveryUrl", federationUrl.String())
			err = config.DiscoverFederation()
			if err != nil {
				return nil, err
			}
		}
	}

	if dest_url.Host != "" {
		if dest_url.Scheme == "osdf" || dest_url.Scheme == "stash" {
			dest_url.Path = "/" + path.Join(dest_url.Host, dest_url.Path)
		} else if dest_url.Scheme == "pelican" {
			config.SetFederation(config.FederationDiscovery{})
			federationUrl, _ := url.Parse(dest_url.String())
			federationUrl.Scheme = "https"
			federationUrl.Path = ""
			viper.Set("Federation.DiscoveryUrl", federationUrl.String())
			err = config.DiscoverFederation()
			if err != nil {
				return nil, err
			}
		}
	}

	sourceScheme, _ := getTokenName(sourceURL)
	destScheme, _ := getTokenName(dest_url)

	understoodSchemes := []string{"stash", "file", "osdf", "pelican", ""}

	_, foundSource := Find(understoodSchemes, sourceScheme)
	if !foundSource {
		log.Errorln("Do not understand source scheme:", sourceURL.Scheme)
		return nil, errors.New("Do not understand source scheme")
	}

	_, foundDest := Find(understoodSchemes, destScheme)
	if !foundDest {
		log.Errorln("Do not understand destination scheme:", sourceURL.Scheme)
		return nil, errors.New("Do not understand destination scheme")
	}

	payload := payloadStruct{}
	parseJobAd(&payload)

	isPut := destScheme == "stash" || destScheme == "osdf" || destScheme == "pelican"

	var localPath string
	var remoteURL *url.URL
	if isPut {
		log.Debugln("Detected object write to remote federation object", dest_url.Path)
		localPath = sourceFile
		remoteURL = dest_url
	} else {

		if dest_url.Scheme == "file" {
			destination = dest_url.Path
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

	payload.version = config.GetVersion()

	//Fill out the payload as much as possible
	payload.filename = sourceURL.Path

	start := time.Now()
	payload.start1 = start.Unix()

	// Go thru the download methods
	success := false

	// switch statement?
	var downloaded int64 = 0

	te := NewTransferEngine(ctx)
	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()
	tc, err := te.NewClient(options...)
	if err != nil {
		return
	}
	tj, err := tc.NewTransferJob(remoteURL, localPath, isPut, recursive)
	if err != nil {
		return
	}
	if err = tc.Submit(tj); err != nil {
		return
	}
	transferResults, err = tc.Shutdown()
	if err == nil {
		success = true
	}

	end := time.Now()

	for _, result := range transferResults {
		downloaded += result.TransferredBytes
	}

	payload.end1 = end.Unix()

	payload.timestamp = payload.end1
	payload.downloadTime = int64(end.Sub(start).Seconds())

	if success {
		payload.status = "Success"

		// Get the final size of the download file
		payload.fileSize = downloaded
		payload.downloadSize = downloaded
		return transferResults, nil
	} else {
		payload.status = "Fail"
		return transferResults, err
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
	rand.Shuffle(len(ipv4s), func(i, j int) { ipv4s[i], ipv4s[j] = ipv4s[j], ipv4s[i] })
	rand.Shuffle(len(ipv6s), func(i, j int) { ipv6s[i], ipv6s[j] = ipv6s[j], ipv6s[i] })

	// Always prefer IPv4
	return append(ipv4s, ipv6s...)

}

func parseJobAd(payload *payloadStruct) {

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
		log.Warningln("Can not read .job.ad file", err)
	}

	// Get all matches from file
	// Note: This appears to be invalid regex but is the only thing that appears to work. This way it successfully finds our matches
	classadRegex, e := regexp.Compile(`^*\s*(Owner|ProjectName)\s=\s"(.*)"`)
	if e != nil {
		log.Fatal(e)
	}

	matches := classadRegex.FindAll(b, -1)
	for _, match := range matches {
		matchString := strings.TrimSpace(string(match))

		if strings.HasPrefix(matchString, "Owner") {
			matchParts := strings.Split(strings.TrimSpace(matchString), "=")

			if len(matchParts) == 2 { // just confirm we get 2 parts of the string
				matchValue := strings.TrimSpace(matchParts[1])
				matchValue = strings.Trim(matchValue, "\"") //trim any "" around the match if present
				payload.Owner = matchValue
			}
		}

		if strings.HasPrefix(matchString, "ProjectName") {
			matchParts := strings.Split(strings.TrimSpace(matchString), "=")

			if len(matchParts) == 2 { // just confirm we get 2 parts of the string
				matchValue := strings.TrimSpace(matchParts[1])
				matchValue = strings.Trim(matchValue, "\"") //trim any "" around the match if present
				payload.ProjectName = matchValue
			}
		}
	}

}
