/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	grab "github.com/opensaucerer/grab/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/param"
)

var (
	progressCtrOnce sync.Once
	progressCtr     *mpb.Progress
)

type StoppedTransferError struct {
	Err string
}

// The progress container object creates several
// background goroutines.  Instead of creating the object
// globally, create it on first use.  This avoids having
// the progress container routines launch in the server.
func getProgressContainer() *mpb.Progress {
	progressCtrOnce.Do(func() {
		progressCtr = mpb.New()
	})
	return progressCtr
}

func (e *StoppedTransferError) Error() string {
	return e.Err
}

type HttpErrResp struct {
	Code int
	Err  string
}

func (e *HttpErrResp) Error() string {
	return e.Err
}

// SlowTransferError is an error that is returned when a transfer takes longer than the configured timeout
type SlowTransferError struct {
	BytesTransferred int64
	BytesPerSecond   int64
	BytesTotal       int64
	Duration         time.Duration
}

func (e *SlowTransferError) Error() string {
	return "cancelled transfer, too slow.  Detected speed: " +
		ByteCountSI(e.BytesPerSecond) +
		"/s, total transferred: " +
		ByteCountSI(e.BytesTransferred) +
		", total transfer time: " +
		e.Duration.String()
}

func (e *SlowTransferError) Is(target error) bool {
	_, ok := target.(*SlowTransferError)
	return ok
}

type FileDownloadError struct {
	Text string
	Err  error
}

func (e *FileDownloadError) Error() string {
	return e.Text
}

func (e *FileDownloadError) Unwrap() error {
	return e.Err
}

// Determines whether or not we can interact with the site HTTP proxy
func IsProxyEnabled() bool {
	if _, isSet := os.LookupEnv("http_proxy"); !isSet {
		return false
	}
	if param.Client_DisableHttpProxy.GetBool() {
		return false
	}
	return true
}

// Determine whether we are allowed to skip the proxy as a fallback
func CanDisableProxy() bool {
	return !param.Client_DisableProxyFallback.GetBool()
}

// ConnectionSetupError is an error that is returned when a connection to the remote server fails
type ConnectionSetupError struct {
	URL string
	Err error
}

func (e *ConnectionSetupError) Error() string {
	if e.Err != nil {
		if len(e.URL) > 0 {
			return "failed connection setup to " + e.URL + ": " + e.Err.Error()
		} else {
			return "failed connection setup: " + e.Err.Error()
		}
	} else {
		return "Connection to remote server failed"
	}

}

func (e *ConnectionSetupError) Unwrap() error {
	return e.Err
}

func (e *ConnectionSetupError) Is(target error) bool {
	_, ok := target.(*ConnectionSetupError)
	return ok
}

// HasPort test the host if it includes a port
func HasPort(host string) bool {
	var checkPort = regexp.MustCompile("^.*:[0-9]+$")
	return checkPort.MatchString(host)
}

type TransferDetails struct {
	// Url is the url.URL of the cache and port
	Url url.URL

	// Proxy specifies if a proxy should be used
	Proxy bool

	// Specifies the pack option in the transfer URL
	PackOption string
}

// NewTransferDetails creates the TransferDetails struct with the given cache
func NewTransferDetails(cache namespaces.Cache, opts TransferDetailsOptions) []TransferDetails {
	details := make([]TransferDetails, 0)
	var cacheEndpoint string
	if opts.NeedsToken {
		cacheEndpoint = cache.AuthEndpoint
	} else {
		cacheEndpoint = cache.Endpoint
	}

	// Form the URL
	cacheURL, err := url.Parse(cacheEndpoint)
	if err != nil {
		log.Errorln("Failed to parse cache:", cache, "error:", err)
		return nil
	}
	if cacheURL.Host == "" {
		// Assume the cache is just a hostname
		cacheURL.Host = cacheEndpoint
		cacheURL.Path = ""
		cacheURL.Scheme = ""
		cacheURL.Opaque = ""
	}
	log.Debugf("Parsed Cache: %s\n", cacheURL.String())
	if opts.NeedsToken {
		cacheURL.Scheme = "https"
		if !HasPort(cacheURL.Host) {
			// Add port 8444 and 8443
			cacheURL.Host += ":8444"
			details = append(details, TransferDetails{
				Url:        *cacheURL,
				Proxy:      false,
				PackOption: opts.PackOption,
			})
			// Strip the port off and add 8443
			cacheURL.Host = cacheURL.Host[:len(cacheURL.Host)-5] + ":8443"
		}
		// Whether port is specified or not, add a transfer without proxy
		details = append(details, TransferDetails{
			Url:        *cacheURL,
			Proxy:      false,
			PackOption: opts.PackOption,
		})
	} else {
		cacheURL.Scheme = "http"
		if !HasPort(cacheURL.Host) {
			cacheURL.Host += ":8000"
		}
		isProxyEnabled := IsProxyEnabled()
		details = append(details, TransferDetails{
			Url:        *cacheURL,
			Proxy:      isProxyEnabled,
			PackOption: opts.PackOption,
		})
		if isProxyEnabled && CanDisableProxy() {
			details = append(details, TransferDetails{
				Url:        *cacheURL,
				Proxy:      false,
				PackOption: opts.PackOption,
			})
		}
	}

	return details
}

type TransferResults struct {
	Error           error
	TransferedBytes int64
	Attempts        []Attempt
}

type Attempt struct {
	Number            int    // indicates which attempt this is
	TransferFileBytes int64  // how much each attempt downloaded
	TimeToFirstByte   int64  // how long it took to download the first byte
	TransferEndTime   int64  // when the transfer ends
	Endpoint          string // which origin did it use
	ServerVersion     string // TODO: figure out how to get this???
	Error             error  // what error the attempt returned (if any)
}

type TransferDetailsOptions struct {
	NeedsToken bool
	PackOption string
}

type CacheInterface interface{}

func GenerateTransferDetailsUsingCache(cache CacheInterface, opts TransferDetailsOptions) []TransferDetails {
	if directorCache, ok := cache.(namespaces.DirectorCache); ok {
		return NewTransferDetailsUsingDirector(directorCache, opts)
	} else if cache, ok := cache.(namespaces.Cache); ok {
		return NewTransferDetails(cache, opts)
	}
	return nil
}

func download_http(sourceUrl *url.URL, destination string, payload *payloadStruct, namespace namespaces.Namespace, recursive bool, tokenName string) (transferResults []TransferResults, err error) {
	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic occurred in download_http:", r)
			ret := fmt.Sprintf("Unrecoverable error (panic) occurred in download_http: %v", r)
			err = errors.New(ret)

			// Attempt to add the panic to the error accumulator
			AddError(errors.New(ret))
		}
	}()

	packOption := sourceUrl.Query().Get("pack")
	if packOption != "" {
		log.Debugln("Will use unpack option value", packOption)
	}
	sourceUrl = &url.URL{Path: sourceUrl.Path}

	var token string
	if namespace.UseTokenOnRead {
		var err error
		token, err = getToken(sourceUrl, namespace, false, tokenName)
		if err != nil {
			log.Errorln("Failed to get token though required to read from this namespace:", err)
			return nil, err
		}
	}

	// Check the env var "USE_OSDF_DIRECTOR" and decide if ordered caches should come from director
	var transfers []TransferDetails
	var files []string
	directorUrl := param.Federation_DirectorUrl.GetString()
	closestNamespaceCaches, err := GetCachesFromNamespace(namespace, directorUrl != "")
	if err != nil {
		log.Errorln("Failed to get namespaced caches (treated as non-fatal):", err)
	}

	log.Debugln("Matched caches:", closestNamespaceCaches)

	// Make sure we only try as many caches as we have
	cachesToTry := CachesToTry
	if cachesToTry > len(closestNamespaceCaches) {
		cachesToTry = len(closestNamespaceCaches)
	}
	log.Debugln("Trying the caches:", closestNamespaceCaches[:cachesToTry])

	if recursive {
		var err error
		files, err = walkDavDir(sourceUrl, namespace, token, "", false)
		if err != nil {
			log.Errorln("Error from walkDavDir", err)
			return nil, err
		}
	} else {
		files = append(files, sourceUrl.Path)
	}

	for _, cache := range closestNamespaceCaches[:cachesToTry] {
		// Parse the cache URL
		log.Debugln("Cache:", cache)
		td := TransferDetailsOptions{
			NeedsToken: namespace.ReadHTTPS || namespace.UseTokenOnRead,
			PackOption: packOption,
		}
		transfers = append(transfers, GenerateTransferDetailsUsingCache(cache, td)...)
	}

	if len(transfers) > 0 {
		log.Debugln("Transfers:", transfers[0].Url.Opaque)
	} else {
		log.Debugln("No transfers possible as no caches are found")
		return nil, errors.New("No transfers possible as no caches are found")
	}
	// Create the wait group and the transfer files
	var wg sync.WaitGroup

	workChan := make(chan string)
	results := make(chan TransferResults, len(files))
	//tf := TransferFiles{files: files}

	if ObjectClientOptions.Recursive && ObjectClientOptions.ProgressBars {
		log.SetOutput(getProgressContainer())
	}
	// Start the workers
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go startDownloadWorker(sourceUrl.Path, destination, token, transfers, payload, &wg, workChan, results)
	}

	// For each file, send it to the worker
	for _, file := range files {
		workChan <- file
	}
	close(workChan)

	// Wait for all the transfers to complete
	wg.Wait()

	var downloadError error = nil
	// Every transfer should send a TransferResults to the results channel
	for i := 0; i < len(files); i++ {
		select {
		case result := <-results:
			transferResults = append(transferResults, result)
			if result.Error != nil {
				downloadError = result.Error
			}
		default:
			// Didn't get a result, that's weird
			downloadError = errors.New("failed to get outputs from one of the transfers")
		}
	}
	// Make sure to close the progressContainer after all download complete
	if ObjectClientOptions.Recursive && ObjectClientOptions.ProgressBars {
		getProgressContainer().Wait()
		log.SetOutput(os.Stdout)
	}
	return transferResults, downloadError

}

func startDownloadWorker(source string, destination string, token string, transfers []TransferDetails, payload *payloadStruct, wg *sync.WaitGroup, workChan <-chan string, results chan<- TransferResults) {

	defer wg.Done()
	var success bool
	var attempts []Attempt
	for file := range workChan {
		// Remove the source from the file path
		newFile := strings.Replace(file, source, "", 1)
		finalDest := path.Join(destination, newFile)
		directory := path.Dir(finalDest)
		var downloaded int64
		err := os.MkdirAll(directory, 0700)
		if err != nil {
			results <- TransferResults{Error: errors.New("Failed to make directory:" + directory)}
			continue
		}
		for idx, transfer := range transfers { // For each transfer (usually 3), populate each attempt given
			var attempt Attempt
			var timeToFirstByte int64
			var serverVersion string
			attempt.Number = idx // Start with 0
			attempt.Endpoint = transfer.Url.Host
			transfer.Url.Path = file
			log.Debugln("Constructed URL:", transfer.Url.String())
			if downloaded, timeToFirstByte, serverVersion, err = DownloadHTTP(transfer, finalDest, token, payload); err != nil {
				log.Debugln("Failed to download:", err)
				transferEndTime := time.Now().Unix()
				var ope *net.OpError
				var cse *ConnectionSetupError
				errorString := "Failed to download from " + transfer.Url.Hostname() + ":" +
					transfer.Url.Port() + " "
				if errors.As(err, &ope) && ope.Op == "proxyconnect" {
					log.Debugln(ope)
					AddrString, _ := os.LookupEnv("http_proxy")
					if ope.Addr != nil {
						AddrString = " " + ope.Addr.String()
					}
					errorString += "due to proxy " + AddrString + " error: " + ope.Unwrap().Error()
				} else if errors.As(err, &cse) {
					errorString += "+ proxy=" + strconv.FormatBool(transfer.Proxy) + ": "
					if sce, ok := cse.Unwrap().(grab.StatusCodeError); ok {
						errorString += sce.Error()
					} else {
						errorString += err.Error()
					}
				} else {
					errorString += "+ proxy=" + strconv.FormatBool(transfer.Proxy) +
						": " + err.Error()
				}
				AddError(&FileDownloadError{errorString, err})
				attempt.TransferFileBytes = downloaded
				attempt.TimeToFirstByte = timeToFirstByte
				attempt.Error = errors.New(errorString)
				attempt.TransferEndTime = int64(transferEndTime)
				attempt.ServerVersion = serverVersion
				attempts = append(attempts, attempt)
				continue
			} else {
				transferEndTime := time.Now().Unix()
				attempt.TransferEndTime = int64(transferEndTime)
				attempt.TimeToFirstByte = timeToFirstByte
				attempt.TransferFileBytes = downloaded
				attempt.ServerVersion = serverVersion
				log.Debugln("Downloaded bytes:", downloaded)
				attempts = append(attempts, attempt)
				success = true
				break
			}

		}
		if !success {
			log.Debugln("Failed to download with HTTP")
			results <- TransferResults{
				TransferedBytes: downloaded,
				Error:           errors.New("failed to download with HTTP"),
				Attempts:        attempts,
			}
			return
		} else {
			results <- TransferResults{
				TransferedBytes: downloaded,
				Error:           nil,
				Attempts:        attempts,
			}
		}
	}
}

func parseTransferStatus(status string) (int, string) {
	parts := strings.SplitN(status, ": ", 2)
	if len(parts) != 2 {
		return 0, ""
	}

	statusCode, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, ""
	}

	return statusCode, strings.TrimSpace(parts[1])
}

// DownloadHTTP - Perform the actual download of the file
// Returns: downloaded size, time to 1st byte downloaded, serverVersion and an error if there is one
func DownloadHTTP(transfer TransferDetails, dest string, token string, payload *payloadStruct) (int64, int64, string, error) {

	// Create the client, request, and context
	client := grab.NewClient()
	transport := config.GetTransport()
	if !transfer.Proxy {
		transport.Proxy = nil
	}
	httpClient, ok := client.HTTPClient.(*http.Client)
	if !ok {
		return 0, 0, "", errors.New("Internal error: implementation is not a http.Client type")
	}
	httpClient.Transport = transport

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Debugln("Transfer URL String:", transfer.Url.String())
	var req *grab.Request
	var err error
	var unpacker *autoUnpacker
	if transfer.PackOption != "" {
		behavior, err := GetBehavior(transfer.PackOption)
		if err != nil {
			return 0, 0, "", err
		}
		if dest == "." {
			dest, err = os.Getwd()
			if err != nil {
				return 0, 0, "", errors.Wrap(err, "Failed to get current directory for destination")
			}
		}
		unpacker = newAutoUnpacker(dest, behavior)
		if req, err = grab.NewRequestToWriter(unpacker, transfer.Url.String()); err != nil {
			return 0, 0, "", errors.Wrap(err, "Failed to create new download request")
		}
	} else if req, err = grab.NewRequest(dest, transfer.Url.String()); err != nil {
		return 0, 0, "", errors.Wrap(err, "Failed to create new download request")
	}

	if token != "" {
		req.HTTPRequest.Header.Set("Authorization", "Bearer "+token)
	}
	// Set the headers
	req.HTTPRequest.Header.Set("X-Transfer-Status", "true")
	req.HTTPRequest.Header.Set("TE", "trailers")
	if payload != nil && payload.ProjectName != "" {
		req.HTTPRequest.Header.Set("User-Agent", payload.ProjectName)
	}
	req.WithContext(ctx)

	// Test the transfer speed every 5 seconds
	t := time.NewTicker(5000 * time.Millisecond)
	defer t.Stop()

	// Progress ticker
	progressTicker := time.NewTicker(500 * time.Millisecond)
	defer progressTicker.Stop()
	downloadLimit := param.Client_MinimumDownloadSpeed.GetInt()

	// If we are doing a recursive, decrease the download limit by the number of likely workers ~5
	if ObjectClientOptions.Recursive {
		downloadLimit /= 5
	}

	// Start the transfer
	log.Debugln("Starting the HTTP transfer...")
	filename := path.Base(dest)
	resp := client.Do(req)
	downloadStart := time.Now()
	// Check the error real quick
	if resp.IsComplete() {
		if err := resp.Err(); err != nil {
			if errors.Is(err, grab.ErrBadLength) {
				err = fmt.Errorf("Local copy of file is larger than remote copy %w", grab.ErrBadLength)
			}
			log.Errorln("Failed to download:", err)
			return 0, 0, "", &ConnectionSetupError{Err: err}
		}
	}
	serverVersion := resp.HTTPResponse.Header.Get("Server")

	// Size of the download
	contentLength := resp.Size()
	// Do a head request for content length if resp.Size is unknown
	if contentLength <= 0 && ObjectClientOptions.ProgressBars {
		headClient := &http.Client{Transport: config.GetTransport()}
		headRequest, _ := http.NewRequest("HEAD", transfer.Url.String(), nil)
		headResponse, err := headClient.Do(headRequest)
		if err != nil {
			log.Errorln("Could not successfully get response for HEAD request")
			return 0, 0, serverVersion, errors.Wrap(err, "Could not determine the size of the remote object")
		}
		defer headResponse.Body.Close()
		contentLengthStr := headResponse.Header.Get("Content-Length")
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			log.Errorln("problem converting content-length to an int", err)
			contentLength = resp.Size()
		}
	}

	var progressBar *mpb.Bar
	if ObjectClientOptions.ProgressBars {
		progressBar = getProgressContainer().AddBar(0,
			mpb.PrependDecorators(
				decor.Name(filename, decor.WCSyncSpaceR),
				decor.CountersKibiByte("% .2f / % .2f"),
			),
			mpb.AppendDecorators(
				decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_GO, 90), ""),
				decor.OnComplete(decor.Name(" ] "), ""),
				decor.OnComplete(decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 5), "Done!"),
			),
		)
	}

	stoppedTransferTimeout := int64(param.Client_StoppedTransferTimeout.GetInt())
	slowTransferRampupTime := int64(param.Client_SlowTransferRampupTime.GetInt())
	slowTransferWindow := int64(param.Client_SlowTransferWindow.GetInt())
	var previousCompletedBytes int64 = 0
	var startBelowLimit int64 = 0
	var previousCompletedTime = time.Now()
	var noProgressStartTime time.Time
	var lastBytesComplete int64
	var timeToFirstByte int64
	timeToFirstByteRecorded := false
	// Loop of the download
Loop:
	for {
		select {
		case <-progressTicker.C:
			if !timeToFirstByteRecorded && resp.BytesComplete() > 1 {
				timeToFirstByte = int64(time.Since(downloadStart))
			}
			if ObjectClientOptions.ProgressBars {
				progressBar.SetTotal(contentLength, false)
				currentCompletedBytes := resp.BytesComplete()
				bytesDelta := currentCompletedBytes - previousCompletedBytes
				previousCompletedBytes = currentCompletedBytes
				currentCompletedTime := time.Now()
				timeElapsed := currentCompletedTime.Sub(previousCompletedTime)
				progressBar.EwmaIncrInt64(bytesDelta, timeElapsed)
				previousCompletedTime = currentCompletedTime
			}

		case <-t.C:
			// Check that progress is being made and that it is not too slow
			if resp.BytesComplete() == lastBytesComplete {
				if noProgressStartTime.IsZero() {
					noProgressStartTime = time.Now()
				} else if time.Since(noProgressStartTime) > time.Duration(stoppedTransferTimeout)*time.Second {
					errMsg := "No progress for more than " + time.Since(noProgressStartTime).Truncate(time.Millisecond).String()
					log.Errorln(errMsg)
					if ObjectClientOptions.ProgressBars {
						progressBar.Abort(true)
						progressBar.Wait()
					}
					return 5, timeToFirstByte, serverVersion, &StoppedTransferError{
						Err: errMsg,
					}
				}
			} else {
				noProgressStartTime = time.Time{}
			}
			lastBytesComplete = resp.BytesComplete()

			// Check if we are downloading fast enough
			if resp.BytesPerSecond() < float64(downloadLimit) {
				// Give the download `slowTransferRampupTime` (default 120) seconds to start
				if resp.Duration() < time.Second*time.Duration(slowTransferRampupTime) {
					continue
				} else if startBelowLimit == 0 {
					warning := []byte("Warning! Downloading too slow...\n")
					status, err := getProgressContainer().Write(warning)
					if err != nil {
						log.Errorln("Problem displaying slow message", err, status)
						continue
					}
					startBelowLimit = time.Now().Unix()
					continue
				} else if (time.Now().Unix() - startBelowLimit) < slowTransferWindow {
					// If the download is below the threshold for less than `SlowTransferWindow` (default 30) seconds, continue
					continue
				}
				// The download is below the threshold for more than `SlowTransferWindow` seconds, cancel the download
				cancel()
				if ObjectClientOptions.ProgressBars {
					progressBar.Abort(true)
					progressBar.Wait()
				}

				log.Errorln("Cancelled: Download speed of ", resp.BytesPerSecond(), "bytes/s", " is below the limit of", downloadLimit, "bytes/s")

				return 0, timeToFirstByte, serverVersion, &SlowTransferError{
					BytesTransferred: resp.BytesComplete(),
					BytesPerSecond:   int64(resp.BytesPerSecond()),
					Duration:         resp.Duration(),
					BytesTotal:       contentLength,
				}

			} else {
				// The download is fast enough, reset the startBelowLimit
				startBelowLimit = 0
			}

		case <-resp.Done:
			// download is complete
			if ObjectClientOptions.ProgressBars {
				downloadError := resp.Err()
				if downloadError != nil {
					log.Errorln(downloadError.Error())
					progressBar.Abort(true)
					progressBar.Wait()
				} else {
					progressBar.SetTotal(contentLength, true)
					// call wait here for the bar to complete and flush
					// If recursive, we still want to use container so keep it open
					if ObjectClientOptions.Recursive {
						progressBar.Wait()
					} else { // Otherwise just close it
						getProgressContainer().Wait()
					}
				}
			}
			break Loop
		}
	}
	//fmt.Printf("\nDownload saved to", resp.Filename)
	err = resp.Err()
	if err != nil {
		// Connection errors
		if errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.ECONNABORTED) {
			return 0, 0, "", &ConnectionSetupError{URL: resp.Request.URL().String()}
		}
		log.Debugln("Got error from HTTP download", err)
		return 0, 0, serverVersion, err
	} else {
		// Check the trailers for any error information
		trailer := resp.HTTPResponse.Trailer
		if errorStatus := trailer.Get("X-Transfer-Status"); errorStatus != "" {
			statusCode, statusText := parseTransferStatus(errorStatus)
			if statusCode != 200 {
				log.Debugln("Got error from file transfer")
				return 0, 0, serverVersion, errors.New("transfer error: " + statusText)
			}
		}
	}
	// Valid responses include 200 and 206.  The latter occurs if the download was resumed after a
	// prior attempt.
	if resp.HTTPResponse.StatusCode != 200 && resp.HTTPResponse.StatusCode != 206 {
		log.Debugln("Got failure status code:", resp.HTTPResponse.StatusCode)
		return 0, 0, serverVersion, &HttpErrResp{resp.HTTPResponse.StatusCode, fmt.Sprintf("Request failed (HTTP status %d): %s",
			resp.HTTPResponse.StatusCode, resp.Err().Error())}
	}

	if unpacker != nil {
		unpacker.Close()
		if err := unpacker.Error(); err != nil {
			return 0, 0, serverVersion, err
		}
	}

	log.Debugln("HTTP Transfer was successful")
	return resp.BytesComplete(), timeToFirstByte, serverVersion, nil
}

type Sizer interface {
	Size() int64
	BytesComplete() int64
}

type ConstantSizer struct {
	size int64
	read atomic.Int64
}

func (cs *ConstantSizer) Size() int64 {
	return cs.size
}

func (cs *ConstantSizer) BytesComplete() int64 {
	return cs.read.Load()
}

// ProgressReader wraps the io.Reader to get progress
// Adapted from https://stackoverflow.com/questions/26050380/go-tracking-post-request-progress
type ProgressReader struct {
	reader io.ReadCloser
	sizer  Sizer
	closed chan bool
}

// Read implements the common read function for io.Reader
func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	if cs, ok := pr.sizer.(*ConstantSizer); ok {
		cs.read.Add(int64(n))
	}
	return n, err
}

// Close implments the close function of io.Closer
func (pr *ProgressReader) Close() error {
	err := pr.reader.Close()
	// Also, send the closed channel a message
	pr.closed <- true
	return err
}

func (pr *ProgressReader) BytesComplete() int64 {
	return pr.sizer.BytesComplete()
}

func (pr *ProgressReader) Size() int64 {
	return pr.sizer.Size()
}

// Recursively uploads a directory with all files and nested dirs, keeping file structure on server side
func UploadDirectory(src string, dest *url.URL, token string, namespace namespaces.Namespace, projectName string) (transferResults []TransferResults, err error) {
	var files []string
	srcUrl := url.URL{Path: src}
	// Get the list of files as well as make any directories on the server end
	files, err = walkDavDir(&srcUrl, namespace, token, dest.Path, true)
	if err != nil {
		return nil, err
	}

	if ObjectClientOptions.ProgressBars {
		log.SetOutput(getProgressContainer())
	}
	var transfer TransferResults
	// Upload all of our files within the proper directories
	for _, file := range files {
		tempDest := url.URL{}
		tempDest.Path, err = url.JoinPath(dest.Path, file)
		if err != nil {
			return nil, err
		}
		transfer, err = UploadFile(file, &tempDest, token, namespace, projectName)
		if err != nil {
			return nil, err
		}
		// Add info from each transfer to transferResults
		transferResults = append(transferResults, transfer)
	}
	// Close progress bar container
	if ObjectClientOptions.ProgressBars {
		getProgressContainer().Wait()
		log.SetOutput(os.Stdout)
	}
	return transferResults, err
}

// UploadFile Uploads a file using HTTP
func UploadFile(src string, origDest *url.URL, token string, namespace namespaces.Namespace, projectName string) (transferResult TransferResults, err error) {
	log.Debugln("In UploadFile")
	log.Debugln("Dest", origDest.String())
	var attempt Attempt
	// Stat the file to get the size (for progress bar)
	fileInfo, err := os.Stat(src)
	if err != nil {
		log.Errorln("Error checking local file ", src, ":", err)
		transferResult.Error = err
		return transferResult, err
	}

	var ioreader io.ReadCloser
	var sizer Sizer
	pack := origDest.Query().Get("pack")
	nonZeroSize := true
	if pack != "" {
		if !fileInfo.IsDir() {
			err = errors.Errorf("Upload with pack=%v only works when input (%v) is a directory", pack, src)
			transferResult.Error = err
			return transferResult, err
		}
		behavior, err := GetBehavior(pack)
		if err != nil {
			transferResult.Error = err
			return transferResult, err
		}
		if behavior == autoBehavior {
			behavior = defaultBehavior
		}
		ap := newAutoPacker(src, behavior)
		ioreader = ap
		sizer = ap
	} else {
		// Try opening the file to send
		file, err := os.Open(src)
		if err != nil {
			log.Errorln("Error opening local file:", err)
			transferResult.Error = err
			return transferResult, err
		}
		ioreader = file
		sizer = &ConstantSizer{size: fileInfo.Size()}
		nonZeroSize = fileInfo.Size() > 0
	}

	// Parse the writeback host as a URL
	writebackhostUrl, err := url.Parse(namespace.WriteBackHost)
	if err != nil {
		transferResult.Error = err
		return transferResult, err
	}

	dest := &url.URL{
		Host:   writebackhostUrl.Host,
		Scheme: "https",
		Path:   origDest.Path,
	}
	attempt.Endpoint = dest.Host
	// Create the wrapped reader and send it to the request
	closed := make(chan bool, 1)
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response)
	reader := &ProgressReader{ioreader, sizer, closed}
	putContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Debugln("Full destination URL:", dest.String())
	var request *http.Request
	// For files that are 0 length, we need to send a PUT request with an nil body
	if nonZeroSize {
		request, err = http.NewRequestWithContext(putContext, "PUT", dest.String(), reader)
	} else {
		request, err = http.NewRequestWithContext(putContext, "PUT", dest.String(), http.NoBody)
	}
	if err != nil {
		log.Errorln("Error creating request:", err)
		transferResult.Error = err
		return transferResult, err
	}
	// Set the authorization header
	request.Header.Set("Authorization", "Bearer "+token)
	if projectName != "" {
		request.Header.Set("User-Agent", projectName)
	}
	var lastKnownWritten int64
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	go doPut(request, responseChan, errorChan)
	uploadStart := time.Now()
	var lastError error = nil

	var progressBar *mpb.Bar
	if ObjectClientOptions.ProgressBars {
		progressBar = getProgressContainer().AddBar(0,
			mpb.PrependDecorators(
				decor.Name(src, decor.WCSyncSpaceR),
				decor.CountersKibiByte("% .2f / % .2f"),
			),
			mpb.AppendDecorators(
				decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_GO, 90), ""),
				decor.OnComplete(decor.Name(" ] "), ""),
				decor.OnComplete(decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 5), "Done!"),
			),
		)
		// Shutdown progress bar at the end of the function
		defer func() {
			if lastError == nil {
				progressBar.SetTotal(reader.Size(), true)
			} else {
				progressBar.Abort(true)
			}
			// If it is recursive, we need to reuse the mpb instance. Closed later
			if ObjectClientOptions.Recursive {
				progressBar.Wait()
			} else { // If not recursive, go ahead and close it
				getProgressContainer().Wait()
			}
		}()
	}
	tickerDuration := 500 * time.Millisecond
	progressTicker := time.NewTicker(tickerDuration)
	firstByteRecorded := false
	defer progressTicker.Stop()

	// Do the select on a ticker, and the writeChan
Loop:
	for {
		select {
		case <-progressTicker.C:
			if !firstByteRecorded && reader.BytesComplete() > 0 {
				attempt.TimeToFirstByte = int64(time.Since(uploadStart))
				firstByteRecorded = true
			}
			if progressBar != nil {
				progressBar.SetTotal(reader.Size(), false)
				progressBar.EwmaSetCurrent(reader.BytesComplete(), tickerDuration)
			}

		case <-t.C:
			// If we are not making any progress, if we haven't written 1MB in the last 5 seconds
			currentRead := reader.BytesComplete()
			log.Debugln("Current read:", currentRead)
			log.Debugln("Last known written:", lastKnownWritten)
			if lastKnownWritten < currentRead {
				// We have made progress!
				lastKnownWritten = currentRead
			} else {
				// No progress has been made in the last 1 second
				log.Errorln("No progress made in last 5 second in upload")
				lastError = errors.New("upload cancelled, no progress in 5 seconds")
				break Loop
			}

		case <-closed:
			// The file has been closed, we're done here
			log.Debugln("File closed")
		case response := <-responseChan:
			attempt.ServerVersion = response.Header.Get("Server")
			if response.StatusCode != 200 {
				log.Errorln("Got failure status code:", response.StatusCode)
				lastError = &HttpErrResp{response.StatusCode, fmt.Sprintf("Request failed (HTTP status %d)",
					response.StatusCode)}
				break Loop
			}
			break Loop

		case err := <-errorChan:
			log.Warningln("Unexpected error when performing upload:", err)
			lastError = err
			break Loop

		}
	}

	if fileInfo.Size() == 0 {
		transferResult.Error = lastError
		attempt.TransferEndTime = time.Now().Unix()

		// Add our attempt fields
		transferResult.Attempts = append(transferResult.Attempts, attempt)
		return transferResult, lastError
	} else {
		log.Debugln("Uploaded bytes:", reader.BytesComplete())
		transferResult.TransferedBytes = reader.BytesComplete()
		attempt.TransferEndTime = time.Now().Unix()

		// Add our attempt fields
		transferResult.Attempts = append(transferResult.Attempts, attempt)
		return transferResult, lastError
	}

}

// Actually perform the Put request to the server
func doPut(request *http.Request, responseChan chan<- *http.Response, errorChan chan<- error) {
	var UploadClient = &http.Client{Transport: config.GetTransport()}
	client := UploadClient
	dump, _ := httputil.DumpRequestOut(request, false)
	log.Debugf("Dumping request: %s", dump)
	response, err := client.Do(request)
	if err != nil {
		log.Errorln("Error with PUT:", err)
		errorChan <- err
		return
	}
	dump, _ = httputil.DumpResponse(response, true)
	log.Debugf("Dumping response: %s", dump)
	if response.StatusCode != 200 {
		log.Errorln("Error status code:", response.Status)
		log.Debugln("From the server:")
		textResponse, err := io.ReadAll(response.Body)
		if err != nil {
			log.Errorln("Error reading response from server:", err)
			responseChan <- response
			return
		}
		log.Debugln(string(textResponse))
	}
	responseChan <- response

}

func walkDavDir(url *url.URL, namespace namespaces.Namespace, token string, destPath string, upload bool) ([]string, error) {

	// Create the client to walk the filesystem
	rootUrl := *url
	if namespace.DirListHost != "" {
		// Parse the dir list host
		dirListURL, err := url.Parse(namespace.DirListHost)
		if err != nil {
			log.Errorln("Failed to parse dirlisthost from namespaces into URL:", err)
			return nil, err
		}
		rootUrl = *dirListURL

	} else {
		log.Errorln("Host for directory listings is unknown")
		return nil, errors.New("Host for directory listings is unknown")
	}
	log.Debugln("Dir list host: ", rootUrl.String())

	auth := &bearerAuth{token: token}
	c := gowebdav.NewAuthClient(rootUrl.String(), auth)

	// XRootD does not like keep alives and kills things, so turn them off.
	transport := config.GetTransport()
	c.SetTransport(transport)
	var files []string
	var err error
	if upload {
		files, err = walkDirUpload(url.Path, c, destPath)
	} else {
		files, err = walkDir(url.Path, c)
	}
	log.Debugln("Found files:", files)
	return files, err

}

// For uploads, we want to make directories on the server end
func walkDirUpload(path string, client *gowebdav.Client, destPath string) ([]string, error) {
	// List of files to return
	var files []string
	// Whenever this function is called, we should create a new dir on the server side for uploads
	err := client.Mkdir(destPath+path, 0755)
	if err != nil {
		return nil, err
	}
	log.Debugf("Creating directory: %s", destPath+path)

	// Get our list of files
	infos, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, info := range infos {
		newPath := path + "/" + info.Name()
		if info.IsDir() {
			// Recursively call this function to create any nested dir's as well as list their files
			returnedFiles, err := walkDirUpload(newPath, client, destPath)
			if err != nil {
				return nil, err
			}
			files = append(files, returnedFiles...)
		} else {
			// It is a normal file
			files = append(files, newPath)
		}
	}
	return files, err
}

func walkDir(path string, client *gowebdav.Client) ([]string, error) {
	var files []string
	log.Debugln("Reading directory: ", path)
	infos, err := client.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, info := range infos {
		newPath := path + "/" + info.Name()
		if info.IsDir() {
			returnedFiles, err := walkDir(newPath, client)
			if err != nil {
				return nil, err
			}
			files = append(files, returnedFiles...)
		} else {
			// It is a normal file
			files = append(files, newPath)
		}
	}
	return files, nil
}

func StatHttp(dest *url.URL, namespace namespaces.Namespace) (uint64, error) {

	scitoken_contents, err := getToken(dest, namespace, false, "")
	if err != nil {
		return 0, err
	}

	// Parse the writeback host as a URL
	writebackhostUrl, err := url.Parse(namespace.WriteBackHost)
	if err != nil {
		return 0, err
	}
	dest.Host = writebackhostUrl.Host
	dest.Scheme = "https"

	canDisableProxy := CanDisableProxy()
	disableProxy := !IsProxyEnabled()

	var resp *http.Response
	for {
		transport := config.GetTransport()
		if disableProxy {
			log.Debugln("Performing HEAD (without proxy)", dest.String())
			transport.Proxy = nil
		} else {
			log.Debugln("Performing HEAD", dest.String())
		}

		client := &http.Client{Transport: transport}
		req, err := http.NewRequest("HEAD", dest.String(), nil)
		if err != nil {
			log.Errorln("Failed to create HTTP request:", err)
			return 0, err
		}

		if scitoken_contents != "" {
			req.Header.Set("Authorization", "Bearer "+scitoken_contents)
		}

		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if urle, ok := err.(*url.Error); canDisableProxy && !disableProxy && ok && urle.Unwrap() != nil {
			if ope, ok := urle.Unwrap().(*net.OpError); ok && ope.Op == "proxyconnect" {
				log.Warnln("Failed to connect to proxy; will retry without:", ope)
				disableProxy = true
				continue
			}
		}
		log.Errorln("Failed to get HTTP response:", err)
		return 0, err
	}

	if resp.StatusCode == 200 {
		defer resp.Body.Close()
		contentLengthStr := resp.Header.Get("Content-Length")
		if len(contentLengthStr) == 0 {
			log.Errorln("HEAD response did not include Content-Length header")
			return 0, errors.New("HEAD response did not include Content-Length header")
		}
		contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			log.Errorf("Unable to parse Content-Length header value (%s) as integer: %s", contentLengthStr, err)
			return 0, err
		}
		return uint64(contentLength), nil
	} else {
		response_b, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Errorln("Failed to read error message:", err)
			return 0, err
		}
		defer resp.Body.Close()
		return 0, &HttpErrResp{resp.StatusCode, fmt.Sprintf("Request failed (HTTP status %d): %s", resp.StatusCode, string(response_b))}
	}
}
