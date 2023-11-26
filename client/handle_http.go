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

var p = mpb.New()

type StoppedTransferError struct {
	Err string
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
	Error      error
	Downloaded int64
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

func download_http(sourceUrl *url.URL, destination string, payload *payloadStruct, namespace namespaces.Namespace, recursive bool, tokenName string, OSDFDirectorUrl string) (bytesTransferred int64, err error) {

	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("Panic occurred in download_http:", r)
			ret := fmt.Sprintf("Unrecoverable error (panic) occurred in download_http: %v", r)
			err = errors.New(ret)
			bytesTransferred = 0

			// Attempt to add the panic to the error accumulator
			AddError(errors.New(ret))
		}
	}()

	packOption := sourceUrl.Query().Get("pack")
	if packOption != "" {
		log.Debugln("Will use unpack option value", packOption)
	}
	sourceUrl = &url.URL{Path: sourceUrl.Path}

	// Generate the downloadUrl
	var token string
	if namespace.UseTokenOnRead {
		var err error
		token, err = getToken(sourceUrl, namespace, false, tokenName)
		if err != nil {
			log.Errorln("Failed to get token though required to read from this namespace:", err)
			return 0, err
		}
	}

	// Check the env var "USE_OSDF_DIRECTOR" and decide if ordered caches should come from director
	var transfers []TransferDetails
	var files []string
	var closestNamespaceCaches []CacheInterface
	if OSDFDirectorUrl != "" {
		log.Debugln("Using OSDF Director at ", OSDFDirectorUrl)
		closestNamespaceCaches = make([]CacheInterface, len(namespace.SortedDirectorCaches))
		for i, v := range namespace.SortedDirectorCaches {
			closestNamespaceCaches[i] = v
		}
	} else {
		tmpCaches, err := GetCachesFromNamespace(namespace)
		if err != nil {
			log.Errorln("Failed to get namespaced caches (treated as non-fatal):", err)
		}

		closestNamespaceCaches = make([]CacheInterface, len(tmpCaches))
		for i, v := range tmpCaches {
			closestNamespaceCaches[i] = v
		}
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
		files, err = walkDavDir(sourceUrl, namespace)
		if err != nil {
			log.Errorln("Error from walkDavDir", err)
			return 0, err
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
		return 0, errors.New("No transfers possible as no caches are found")
	}
	// Create the wait group and the transfer files
	var wg sync.WaitGroup

	workChan := make(chan string)
	results := make(chan TransferResults, len(files))
	//tf := TransferFiles{files: files}

	// Start the workers
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go startDownloadWorker(sourceUrl.Path, destination, token, transfers, &wg, workChan, results)
	}

	// For each file, send it to the worker
	for _, file := range files {
		workChan <- file
	}
	close(workChan)

	// Wait for all the transfers to complete
	wg.Wait()

	var downloaded int64
	var downloadError error = nil
	// Every transfer should send a TransferResults to the results channel
	for i := 0; i < len(files); i++ {
		select {
		case result := <-results:
			downloaded += result.Downloaded
			if result.Error != nil {
				downloadError = result.Error
			}
		default:
			// Didn't get a result, that's weird
			downloadError = errors.New("failed to get outputs from one of the transfers")
		}
	}

	return downloaded, downloadError

}

func startDownloadWorker(source string, destination string, token string, transfers []TransferDetails, wg *sync.WaitGroup, workChan <-chan string, results chan<- TransferResults) {

	defer wg.Done()
	var success bool
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
		for _, transfer := range transfers {
			transfer.Url.Path = file
			log.Debugln("Constructed URL:", transfer.Url.String())
			if downloaded, err = DownloadHTTP(transfer, finalDest, token); err != nil {
				log.Debugln("Failed to download:", err)
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
				continue
			} else {
				log.Debugln("Downloaded bytes:", downloaded)
				success = true
				break
			}

		}
		if !success {
			log.Debugln("Failed to download with HTTP")
			results <- TransferResults{Error: errors.New("failed to download with HTTP")}
			return
		} else {
			results <- TransferResults{
				Downloaded: downloaded,
				Error:      nil,
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
func DownloadHTTP(transfer TransferDetails, dest string, token string) (int64, error) {

	// Create the client, request, and context
	client := grab.NewClient()
	transport := config.GetTransport()
	if !transfer.Proxy {
		transport.Proxy = nil
	}
	httpClient, ok := client.HTTPClient.(*http.Client)
	if !ok {
		return 0, errors.New("Internal error: implementation is not a http.Client type")
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
			return 0, err
		}
		unpacker = newAutoUnpacker(dest, behavior)
		if req, err = grab.NewRequestToWriter(unpacker, transfer.Url.String()); err != nil {
			return 0, errors.Wrap(err, "Failed to create new download request")
		}
	} else if req, err = grab.NewRequest(dest, transfer.Url.String()); err != nil {
		return 0, errors.Wrap(err, "Failed to create new download request")
	}

	if token != "" {
		req.HTTPRequest.Header.Set("Authorization", "Bearer "+token)
	}
	// Set the headers
	req.HTTPRequest.Header.Set("X-Transfer-Status", "true")
	req.HTTPRequest.Header.Set("TE", "trailers")
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
	// Check the error real quick
	if resp.IsComplete() {
		if err := resp.Err(); err != nil {
			if errors.Is(err, grab.ErrBadLength) {
				err = fmt.Errorf("Local copy of file is larger than remote copy %w", grab.ErrBadLength)
			}
			log.Errorln("Failed to download:", err)
			return 0, &ConnectionSetupError{Err: err}
		}
	}

	// Size of the download
	contentLength := resp.Size()
	// Do a head request for content length if resp.Size is unknown
	if contentLength <= 0 && ObjectClientOptions.ProgressBars {
		headClient := &http.Client{Transport: config.GetTransport()}
		headRequest, _ := http.NewRequest("HEAD", transfer.Url.String(), nil)
		headResponse, err := headClient.Do(headRequest)
		if err != nil {
			log.Errorln("Could not successfully get response for HEAD request")
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
		progressBar = p.AddBar(0,
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
	// Loop of the download
Loop:
	for {
		select {
		case <-progressTicker.C:
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
					return 5, &StoppedTransferError{
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
					status, err := p.Write(warning)
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

				return 0, &SlowTransferError{
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
					p.Wait()
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
			return 0, &ConnectionSetupError{URL: resp.Request.URL().String()}
		}
		log.Debugln("Got error from HTTP download", err)
		return 0, err
	} else {
		// Check the trailers for any error information
		trailer := resp.HTTPResponse.Trailer
		if errorStatus := trailer.Get("X-Transfer-Status"); errorStatus != "" {
			statusCode, statusText := parseTransferStatus(errorStatus)
			if statusCode != 200 {
				log.Debugln("Got error from file transfer")
				return 0, errors.New("transfer error: " + statusText)
			}
		}
	}
	// Valid responses include 200 and 206.  The latter occurs if the download was resumed after a
	// prior attempt.
	if resp.HTTPResponse.StatusCode != 200 && resp.HTTPResponse.StatusCode != 206 {
		log.Debugln("Got failure status code:", resp.HTTPResponse.StatusCode)
		return 0, &HttpErrResp{resp.HTTPResponse.StatusCode, fmt.Sprintf("Request failed (HTTP status %d): %s",
			resp.HTTPResponse.StatusCode, resp.Err().Error())}
	}

	if unpacker != nil {
		unpacker.Close()
		if err := unpacker.Error(); err != nil {
			return 0, err
		}
	}

	log.Debugln("HTTP Transfer was successful")
	return resp.BytesComplete(), nil
}

// ProgressReader wraps the io.Reader to get progress
// Adapted from https://stackoverflow.com/questions/26050380/go-tracking-post-request-progress
type ProgressReader struct {
	reader io.ReadCloser
	read   int64
	size   int64
	closed chan bool
}

// Read implements the common read function for io.Reader
func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	atomic.AddInt64(&pr.read, int64(n))
	return n, err
}

// Close implments the close function of io.Closer
func (pr *ProgressReader) Close() error {
	err := pr.reader.Close()
	// Also, send the closed channel a message
	pr.closed <- true
	return err
}

// UploadFile Uploads a file using HTTP
func UploadFile(src string, origDest *url.URL, token string, namespace namespaces.Namespace) (int64, error) {

	log.Debugln("In UploadFile")
	log.Debugln("Dest", origDest.String())

	// Stat the file to get the size (for progress bar)
	fileInfo, err := os.Stat(src)
	if err != nil {
		log.Errorln("Error checking local file ", src, ":", err)
		return 0, err
	}

	var ioreader io.ReadCloser
	pack := origDest.Query().Get("pack")
	if pack != "" {
		behavior, err := GetBehavior(pack)
		if err != nil {
			return 0, err
		}
		if behavior == autoBehavior {
			behavior = defaultBehavior
		}
		ioreader = newAutoPacker(src, behavior)
	} else {
		// Try opening the file to send
		file, err := os.Open(src)
		if err != nil {
			log.Errorln("Error opening local file:", err)
			return 0, err
		}
		ioreader = file
	}

	// Parse the writeback host as a URL
	writebackhostUrl, err := url.Parse(namespace.WriteBackHost)
	if err != nil {
		return 0, err
	}

	dest := &url.URL{
		Host:   writebackhostUrl.Host,
		Scheme: "https",
		Path:   origDest.Path,
	}

	// Create the wrapped reader and send it to the request
	closed := make(chan bool, 1)
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response)
	reader := &ProgressReader{ioreader, 0, fileInfo.Size(), closed}
	putContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Debugln("Full destination URL:", dest.String())
	var request *http.Request
	// For files that are 0 length, we need to send a PUT request with an nil body
	if fileInfo.Size() > 0 {
		request, err = http.NewRequestWithContext(putContext, "PUT", dest.String(), reader)
	} else {
		request, err = http.NewRequestWithContext(putContext, "PUT", dest.String(), http.NoBody)
	}
	if err != nil {
		log.Errorln("Error creating request:", err)
		return 0, err
	}
	if fileInfo.Mode().IsRegular() {
		request.ContentLength = fileInfo.Size()
	}
	// Set the authorization header
	request.Header.Set("Authorization", "Bearer "+token)
	var lastKnownWritten int64
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	go doPut(request, responseChan, errorChan)
	var lastError error = nil

	// Do the select on a ticker, and the writeChan
Loop:
	for {
		select {
		case <-t.C:
			// If we are not making any progress, if we haven't written 1MB in the last 5 seconds
			currentRead := atomic.LoadInt64(&reader.read)
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
		return 0, lastError
	} else {
		return atomic.LoadInt64(&reader.read), lastError
	}

}

var UploadClient = &http.Client{Transport: config.GetTransport()}

// Actually perform the Put request to the server
func doPut(request *http.Request, responseChan chan<- *http.Response, errorChan chan<- error) {
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

func walkDavDir(url *url.URL, namespace namespaces.Namespace) ([]string, error) {

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
	c := gowebdav.NewClient(rootUrl.String(), "", "")

	// XRootD does not like keep alives and kills things, so turn them off.
	transport := config.GetTransport()
	c.SetTransport(transport)

	files, err := walkDir(url.Path, c)
	log.Debugln("Found files:", files)
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
