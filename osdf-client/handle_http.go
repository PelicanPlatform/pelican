package stashcp

import (
	"context"
	"errors"
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

	grab "github.com/cavaliercoder/grab"
	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"
	"github.com/vbauerster/mpb/v7"
	"github.com/vbauerster/mpb/v7/decor"
)

var env_prefixes = [...] string {"OSG", "OSDF"}

var p = mpb.New()

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
	for _, prefix := range env_prefixes {
		if _, isSet := os.LookupEnv(prefix + "_DISABLE_HTTP_PROXY"); isSet {
			return false
		}
	}
	return true
}

// Determine whether we are allowed to skip the proxy as a fallback
func CanDisableProxy() bool {
	for _, prefix := range env_prefixes {
		if _, isSet := os.LookupEnv(prefix + "_DISABLE_PROXY_FALLBACK"); isSet {
			return false
		}
	}
	return true
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
}

// NewTransferDetails creates the TransferDetails struct with the given cache
func NewTransferDetails(cache Cache, https bool) []TransferDetails {
	details := make([]TransferDetails, 0)
	var cacheEndpoint string
	if https {
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
	if https {
		cacheURL.Scheme = "https"
		if !HasPort(cacheURL.Host) {
			// Add port 8444 and 8443
			cacheURL.Host += ":8444"
			details = append(details, TransferDetails{
				Url:   *cacheURL,
				Proxy: false,
			})
			// Strip the port off and add 8443
			cacheURL.Host = cacheURL.Host[:len(cacheURL.Host)-5] + ":8443"
		}
		// Whether port is specified or not, add a transfer without proxy
		details = append(details, TransferDetails{
			Url:   *cacheURL,
			Proxy: false,
		})
	} else {
		cacheURL.Scheme = "http"
		if !HasPort(cacheURL.Host) {
			cacheURL.Host += ":8000"
		}
		isProxyEnabled := IsProxyEnabled()
		details = append(details, TransferDetails{
			Url:   *cacheURL,
			Proxy: isProxyEnabled,
		})
		if isProxyEnabled && CanDisableProxy() {
			details = append(details, TransferDetails{
				Url:   *cacheURL,
				Proxy: false,
			})
		}
	}

	return details
}

type TransferResults struct {
	Error      error
	Downloaded int64
}

func download_http(source string, destination string, payload *payloadStruct, namespace Namespace, recursive bool, tokenName string) (bytesTransferred int64, err error) {

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

	// Generate the downloadUrl
	var token string
	if namespace.UseTokenOnRead {
		var err error
		sourceUrl := url.URL{Path: source}
		token, err = getToken(&sourceUrl, namespace, false)
		if err != nil {
			log.Errorln("Failed to get token though required to read from this namespace:", err)
			return 0, err
		}
	}

	// Check the env var "USE_OSDF_DIRECTOR" and decide if ordered caches should come from director
	OSDFDirectorUrl, useOSDFDirector := os.LookupEnv("OSDF_DIRECTOR_URL")
	var closestNamespaceCaches []Cache
	if useOSDFDirector {
		log.Debugln("Using OSDF Director at ", OSDFDirectorUrl)
		closestNamespaceCaches, err = GetCachesFromDirector(source, OSDFDirectorUrl)
	} else {
		closestNamespaceCaches, err = GetCachesFromNamespace(namespace)
	}

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
	var transfers []TransferDetails
	downloadUrl := url.URL{Path: source}
	var files []string

	if recursive {
		var err error
		files, err = walkDavDir(&downloadUrl, token, namespace)
		if err != nil {
			log.Errorln("Error from walkDavDir", err)
			return 0, err
		}
	} else {
		files = append(files, source)
	}

	// Generate all of the transfer details to make a list of transfers
	for _, cache := range closestNamespaceCaches[:cachesToTry] {
		// Parse the cache URL
		log.Debugln("Cache:", cache)
		transfers = append(transfers, NewTransferDetails(cache, namespace.ReadHTTPS || namespace.UseTokenOnRead)...)
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
		go startDownloadWorker(source, destination, token, transfers, &wg, workChan, results)
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

// DownloadHTTP - Perform the actual download of the file
func DownloadHTTP(transfer TransferDetails, dest string, token string) (int64, error) {

	// Create the client, request, and context
	client := grab.NewClient()
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          30,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	if !transfer.Proxy {
		transport.Proxy = nil
	}
	client.HTTPClient.Transport = &transport

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Debugln("Transfer URL String:", transfer.Url.String())
	req, _ := grab.NewRequest(dest, transfer.Url.String())
	if token != "" {
		req.HTTPRequest.Header.Set("Authorization", "Bearer "+token)
	}
	req.WithContext(ctx)

	// Test the transfer speed every 5 seconds
	t := time.NewTicker(5000 * time.Millisecond)
	defer t.Stop()

	// Progress ticker
	progressTicker := time.NewTicker(500 * time.Millisecond)
	defer progressTicker.Stop()

	// Store the last downloaded amount, and the bottom limit of the download
	// Check the environment variable STASHCP_MINIMUM_DOWNLOAD_SPEED
	downloadLimitStr := os.Getenv("STASHCP_MINIMUM_DOWNLOAD_SPEED")
	var downloadLimit int64 = 1024 * 100
	if downloadLimitStr != "" {
		var err error
		downloadLimit, err = strconv.ParseInt(downloadLimitStr, 10, 64)
		if err != nil {
			log.Errorln("Environment variable STASHCP_MINIMUM_DOWNLOAD_SPEED=", downloadLimitStr, " is not parsable as integer:", err, "defaulting to 1MB/s")
		}
	}
	// If we are doing a recursive, decrease the download limit by the number of likely workers ~5
	if Options.Recursive {
		downloadLimit /= 5
	}

	// Start the transfer
	log.Debugln("Starting the HTTP transfer...")
	filename := path.Base(dest)
	resp := client.Do(req)
	// Check the error real quick
	if resp.IsComplete() {
		if err := resp.Err(); err != nil {
			log.Errorln("Failed to download:", err)
			return 0, &ConnectionSetupError{Err: err}
		}
	}

	var progressBar *mpb.Bar
	if Options.ProgressBars {
		progressBar = p.AddBar(0,
			mpb.PrependDecorators(
				decor.Name(filename, decor.WCSyncSpaceR),
				decor.CountersKibiByte("% .2f / % .2f"),
			),
			mpb.AppendDecorators(
				decor.EwmaETA(decor.ET_STYLE_GO, 90),
				decor.Name(" ] "),
				decor.EwmaSpeed(decor.UnitKiB, "% .2f", 20),
			),
		)
	}

	var previousCompletedBytes int64 = 0
	var previousCompletedTime = time.Now()
	var startBelowLimit int64 = 0
	// Loop of the download
Loop:
	for {
		select {
		case <-progressTicker.C:
			if Options.ProgressBars {
				progressBar.SetTotal(resp.Size, false)
				currentCompletedBytes := resp.BytesComplete()
				progressBar.IncrInt64(currentCompletedBytes - previousCompletedBytes)
				previousCompletedBytes = currentCompletedBytes
				currentCompletedTime := time.Now()
				progressBar.DecoratorEwmaUpdate(currentCompletedTime.Sub(previousCompletedTime))
				previousCompletedTime = currentCompletedTime
			}

		case <-t.C:

			// Check if we are downloading fast enough
			if resp.BytesPerSecond() < float64(downloadLimit) {
				// Give the download 120 seconds to start
				if resp.Duration() < time.Second*120 {
					continue
				} else if startBelowLimit == 0 {
					log.Warnln("Download speed of ", resp.BytesPerSecond(), "bytes/s", " is below the limit of", downloadLimit, "bytes/s")
					startBelowLimit = time.Now().Unix()
					continue
				} else if (time.Now().Unix() - startBelowLimit) < 30 {
					// If the download is below the threshold for less than 30 seconds, continue
					continue
				}
				// The download is below the threshold for more than 30 seconds, cancel the download
				cancel()
				if Options.ProgressBars {
					var cancelledProgressBar = p.AddBar(0,
						mpb.BarQueueAfter(progressBar),
						mpb.BarFillerClearOnComplete(),
						mpb.PrependDecorators(
							decor.Name(filename, decor.WC{W: len(filename) + 1, C: decor.DidentRight}),
							decor.OnComplete(decor.Name(filename, decor.WCSyncSpaceR), "cancelled, too slow!"),
							decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_MMSS, 0, decor.WCSyncWidth), ""),
						),
						mpb.AppendDecorators(
							decor.OnComplete(decor.Percentage(decor.WC{W: 5}), ""),
						),
					)
					progressBar.SetTotal(resp.Size, true)
					cancelledProgressBar.SetTotal(resp.Size, true)
				}

				return 0, &SlowTransferError{
					BytesTransferred: resp.BytesComplete(),
					BytesPerSecond:   int64(resp.BytesPerSecond()),
					Duration:         resp.Duration(),
					BytesTotal:       resp.Size,
				}

			} else {
				// The download is fast enough, reset the startBelowLimit
				startBelowLimit = 0
			}

		case <-resp.Done:
			// download is complete
			if Options.ProgressBars {
				downloadError := resp.Err()
				completeMsg := "done!"
				if downloadError != nil {
					completeMsg = downloadError.Error()
				}
				var doneProgressBar = p.AddBar(resp.Size,
					mpb.BarQueueAfter(progressBar),
					mpb.BarFillerClearOnComplete(),
					mpb.PrependDecorators(
						decor.Name(filename, decor.WC{W: len(filename) + 1, C: decor.DidentRight}),
						decor.OnComplete(decor.Name(filename, decor.WCSyncSpaceR), completeMsg),
						decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_MMSS, 0, decor.WCSyncWidth), ""),
					),
					mpb.AppendDecorators(
						decor.OnComplete(decor.Percentage(decor.WC{W: 5}), ""),
					),
				)

				progressBar.SetTotal(resp.Size, true)
				doneProgressBar.SetTotal(resp.Size, true)
			}
			break Loop
		}
	}
	//fmt.Printf("\nDownload saved to", resp.Filename)
	err := resp.Err()
	if err != nil {
		// Connection errors
		if errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.ECONNABORTED) {
			return 0, &ConnectionSetupError{URL: resp.Request.URL().String()}
		}
		log.Debugln("Got error from HTTP download", err)
		return 0, err
	}
        // Valid responses include 200 and 206.  The latter occurs if the download was resumed after a
        // prior attempt.
	if resp.HTTPResponse.StatusCode != 200 && resp.HTTPResponse.StatusCode != 206 {
		log.Debugln("Got failure status code:", resp.HTTPResponse.StatusCode)
		return 0, errors.New("failure status code")
	}
	log.Debugln("HTTP Transfer was successful")
	return resp.BytesComplete(), nil
}

// ProgressReader wraps the io.Reader to get progress
// Adapted from https://stackoverflow.com/questions/26050380/go-tracking-post-request-progress
type ProgressReader struct {
	file   *os.File
	read   int64
	size   int64
	closed chan bool
}

// Read implements the common read function for io.Reader
func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.file.Read(p)
	atomic.AddInt64(&pr.read, int64(n))
	return n, err
}

// Close implments the close function of io.Closer
func (pr *ProgressReader) Close() error {
	err := pr.file.Close()
	// Also, send the closed channel a message
	pr.closed <- true
	return err
}

// UploadFile Uploads a file using HTTP
func UploadFile(src string, dest *url.URL, token string, namespace Namespace) (int64, error) {

	log.Debugln("In UploadFile")
	log.Debugln("Dest", dest.String())
	// Try opening the file to send
	file, err := os.Open(src)
	if err != nil {
		log.Errorln("Error opening local file:", err)
		return 0, err
	}
	// Stat the file to get the size (for progress bar)
	fileInfo, err := file.Stat()
	if err != nil {
		log.Errorln("Error stating local file ", src, ":", err)
		return 0, err
	}
	// Parse the writeback host as a URL
	writebackhostUrl, err := url.Parse(namespace.WriteBackHost)
	if err != nil {
		return 0, err
	}
	dest.Host = writebackhostUrl.Host
	dest.Scheme = "https"

	// Check if the destination is a directory
	isDestDir, err := IsDir(dest, token, namespace)
	if err != nil {
		log.Warnln("Received an error from checking if dest was a directory.  Going to continue as if there was no error")
	}
	if isDestDir {
		// Set the destination as the basename of the source
		dest.Path = path.Join(dest.Path, path.Base(src))
		log.Debugln("Destination", dest.Path, "is a directory")
	}

	// Create the wrapped reader and send it to the request
	closed := make(chan bool, 1)
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response)
	reader := &ProgressReader{file, 0, fileInfo.Size(), closed}
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
	request.ContentLength = fileInfo.Size()
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
				lastError = errors.New("failure status code")
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

var UploadClient = &http.Client{}

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

func IsDir(dirUrl *url.URL, token string, namespace Namespace) (bool, error) {
	connectUrl := url.URL{}
	if namespace.DirListHost != "" {
		// Parse the dir list host
		dirListURL, err := url.Parse(namespace.DirListHost)
		if err != nil {
			log.Errorln("Failed to parse dirlisthost from namespaces into URL:", err)
			return false, err
		}
		connectUrl = *dirListURL

	} else {
		//rootUrl.Path = ""
		connectUrl.Host = "stash.osgconnect.net:1094"
		connectUrl.Scheme = "http"
	}

	c := gowebdav.NewClient(connectUrl.String(), "", "")
	//c.SetHeader("Authorization", "Bearer "+token)

	// The path can have special characters in it like '#' and '?', so we have to collect
	// the path parts and join them together
	finalPath := dirUrl.Path
	if dirUrl.RawQuery != "" {
		finalPath += "?" + dirUrl.RawQuery
	}
	if dirUrl.Fragment != "" {
		finalPath += "#" + dirUrl.Fragment
	}
	log.Debugln("Final webdav checked path:", finalPath)
	info, err := c.Stat(finalPath)
	if err != nil {
		log.Debugln("Failed to ReadDir:", err, "for URL:", dirUrl.String())
		return false, err
	}
	log.Debugln("Got isDir response:", info.IsDir())
	return info.IsDir(), nil

}

func walkDavDir(url *url.URL, token string, namespace Namespace) ([]string, error) {

	// First, check if the url is a directory
	isDir, err := IsDir(url, token, namespace)
	if err != nil {
		log.Errorln("Failed to check if path", url.Path, " is directory:", err)
		return nil, err
	}
	if !isDir {
		log.Errorln("Path ", url.Path, " is not a directory.")
		return nil, errors.New("path " + url.Path + " is not a directory")
	}

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
		rootUrl.Path = ""
		rootUrl.Host = "stash.osgconnect.net:1094"
		rootUrl.Scheme = "http"
	}
	log.Debugln("Dir list host: ", rootUrl.String())
	c := gowebdav.NewClient(rootUrl.String(), "", "")

	// XRootD does not like keep alives and kills things, so turn them off.
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   true,
	}
	c.SetTransport(&transport)

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
