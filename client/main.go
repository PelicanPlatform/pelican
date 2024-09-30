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
	"fmt"
	"net"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"math/rand"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Number of caches to attempt to use in any invocation
var ObjectServersToTry int = 3

// Our own FileInfo structure to hold information about a file
// NOTE: this was created to provide more flexibility to information on a file. The fs.FileInfo interface was causing some issues like not always returning a Name attribute
// ALSO NOTE: the fields are exported so they can be marshalled into JSON, it does not work otherwise
type FileInfo struct {
	Name         string
	Size         int64
	ModTime      time.Time
	IsCollection bool
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

	dirResp, err := GetDirectorInfoForPath(ctx, destUri.Path, pelicanURL.directorUrl, false, "", "")
	if err != nil {
		return nil, err
	}

	token := newTokenGenerator(destUri, &dirResp, false, true)
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionTokenLocation{}:
			token.SetTokenLocation(option.Value().(string))
		case identTransferOptionAcquireToken{}:
			token.EnableAcquire = option.Value().(bool)
		case identTransferOptionToken{}:
			token.SetToken(option.Value().(string))
		}
	}

	if dirResp.XPelNsHdr.RequireToken {
		tokenContents, err := token.get()
		if err != nil || tokenContents == "" {
			return nil, errors.Wrap(err, "failed to get token for transfer")
		}
	}

	if statInfo, err := statHttp(destUri, dirResp, token); err != nil {
		return nil, errors.Wrap(err, "failed to do the stat")
	} else {
		return &statInfo, nil
	}
}

// Check the cache information of a remote cache
func DoCacheInfo(ctx context.Context, destination string, options ...TransferOption) (age int, size int64, err error) {

	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to do cache info:", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) while check file size: %v", r)
			err = errors.New(ret)
			return
		}
	}()

	destUri, err := url.Parse(destination)
	if err != nil {
		log.Errorln("Failed to parse destination URL")
		return
	}

	// Check if we understand the found url scheme
	err = schemeUnderstood(destUri.Scheme)
	if err != nil {
		return
	}

	te, err := NewTransferEngine(ctx)
	if err != nil {
		return
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
	return tc.CacheInfo(ctx, destUri)
}

func GetObjectServerHostnames(ctx context.Context, testFile string) (urls []string, err error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return
	}

	parsedDirResp, err := GetDirectorInfoForPath(ctx, testFile, fedInfo.DirectorEndpoint, false, "", "")
	if err != nil {
		return
	}
	for _, objectServer := range parsedDirResp.ObjectServers {
		urls = append(urls, objectServer.Hostname())
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

// Given a response from the director with sorted object servers, incorporate any "preferred" servers (origins/caches) that
// may be passed in from the command line. This should handle the special '+' logic -- if the user provides a list of servers
// and no +, it means they ONLY want to use the provided servers. Otherwise, we prefer those servers, but also incorporate the
// servers provided by the Director.
func generateSortedObjServers(dirResp server_structs.DirectorResponse, preferredCaches []*url.URL) (objectServers []*url.URL, err error) {
	var appendCaches bool
	// The global cache override is set
	if len(preferredCaches) > 0 {
		var preferredObjectServers []*url.URL
		for idx, preferredCache := range preferredCaches {
			cacheUrl := preferredCache.String()
			// If the preferred cache is empty, return an error
			if cacheUrl == "" {
				err = errors.New("Preferred server was specified as an empty string")
				return
			} else if cacheUrl == "+" {
				// If we have a '+' in our list, the user wants to prepend the preferred caches to the "normal" list of caches
				// if the cache is a '+', verify it is at the end of our list, if not, return an error
				if idx != len(preferredCaches)-1 {
					err = errors.New("The special character '+' must be the last item in the list of preferred servers")
					return
				}
				// We want to signify that we want to append the "normal" cache list
				appendCaches = true
			} else {
				// We have a normal item in the preferred cache list
				log.Debugf("Using the server (%s) from the config override\n", preferredCache)
				preferredObjectServers = append(preferredObjectServers, preferredCache)
			}
		}
		objectServers = preferredObjectServers
		// No +, no mo problems -- err, I mean, no more object servers
		if !appendCaches {
			return
		}
	}

	log.Debugln("Using the returned sources from the director")
	// We may have some servers from the preferred list
	objectServers = append(objectServers, dirResp.ObjectServers...)

	if log.IsLevelEnabled(log.DebugLevel) || log.IsLevelEnabled(log.TraceLevel) {
		oHosts := make([]string, len(objectServers))
		for idx, oServer := range objectServers {
			simpleUrl := url.URL{
				Scheme: oServer.Scheme,
				Host:   oServer.Host,
			}
			oHosts[idx] = simpleUrl.String()
		}
		if len(oHosts) <= 6 {
			log.Debugln("Matched object servers:", strings.Join(oHosts, ", "))
		} else {
			log.Debugf("Matched object servers: %s ... (plus %d more)", strings.Join(oHosts[0:6], ", "), len(oHosts)-6)
			log.Traceln("matched object servers continued:", oHosts[6:])
		}
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

	dirResp, err := GetDirectorInfoForPath(ctx, remoteObjectUrl.Path, pelicanURL.directorUrl, false, "", "")
	if err != nil {
		return nil, err
	}

	// Get our token if needed
	token := newTokenGenerator(remoteObjectUrl, &dirResp, false, true)
	collectionsOverride := ""
	for _, option := range options {
		switch option.Ident() {
		case identTransferOptionTokenLocation{}:
			token.SetTokenLocation(option.Value().(string))
		case identTransferOptionAcquireToken{}:
			token.EnableAcquire = option.Value().(bool)
		case identTransferOptionToken{}:
			token.SetToken(option.Value().(string))
		case identTransferOptionCollectionsUrl{}:
			collectionsOverride = option.Value().(string)
		}
	}

	if dirResp.XPelNsHdr.RequireToken {
		tokenContents, err := token.get()
		if err != nil || tokenContents == "" {
			return nil, errors.Wrap(err, "failed to get token for transfer")
		}
	}
	if collectionsOverride != "" {
		collectionsOverrideUrl, err := url.Parse(collectionsOverride)
		if err != nil {
			return nil, errors.Wrap(err, "unable to parse collections URL override")
		}
		dirResp.XPelNsHdr.CollectionsUrl = collectionsOverrideUrl
	}

	fileInfos, err = listHttp(remoteObjectUrl, dirResp, token)
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
			log.Debugln("Panic captured while attempting to perform transfer:", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured: %v", r)
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
	isGet := sourceScheme == "stash" || sourceScheme == "osdf" || sourceScheme == "pelican"

	var localPath string
	var remoteURL *url.URL
	if isPut && isGet {
		if err = schemeUnderstood(destScheme); err != nil {
			return nil, err
		}
		if err = schemeUnderstood(sourceScheme); err != nil {
			return nil, err
		}
		localPath = "/dev/null"
		remoteURL = destURL
	} else if isPut {
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
	var tj *TransferJob
	if isGet && isPut {
		tj, err = tc.NewCopyJob(context.Background(), sourceURL, remoteURL, options...)
	} else {
		tj, err = tc.NewTransferJob(context.Background(), remoteURL, localPath, isPut, recursive)
	}
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
