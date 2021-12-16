package main

import (
	"context"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	grab "github.com/cavaliercoder/grab"
	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"
	"github.com/vbauerster/mpb/v7"
	"github.com/vbauerster/mpb/v7/decor"
)

var p = mpb.New()

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
func NewTransferDetails(cache string, https bool) []TransferDetails {
	details := make([]TransferDetails, 0)

	_, canDisableProxy := os.LookupEnv("OSG_DISABLE_PROXY_FALLBACK")
	canDisableProxy = !canDisableProxy

	// Form the URL
	cacheURL, err := url.Parse(cache)
	if err != nil {
		log.Errorln("Failed to parse cache:", cache, "error:", err)
		return nil
	}
	if cacheURL.Host == "" {
		// Assume the cache is just a hostname
		cacheURL.Host = cache
		cacheURL.Path = ""
	}
	log.Debugf("Parsed Cache: %+v\n", cacheURL)
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
			cacheURL.Host = cacheURL.Host[:len(cacheURL.Host) - 5] + ":8443"
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
		details = append(details, TransferDetails{
			Url:   *cacheURL,
			Proxy: true,
		})
		if canDisableProxy {
			details = append(details, TransferDetails{
				Url:   *cacheURL,
				Proxy: false,
			})
		}
	}


	return details
}

func download_http(source string, destination string, payload *payloadStruct, namespace Namespace, recursive bool) error {
	// Generate the url
	var token string
	if namespace.UseTokenOnRead {
		var err error
		token, err = getToken()
		if err != nil {
			log.Errorln("Failed to get token though required to read from this namespace:", err)
			return err
		}
	}

	cacheListName := "xroot"
	if namespace.ReadHTTPS || namespace.UseTokenOnRead {
		cacheListName = "xroots"
	}
	if len(nearest_cache_list) == 0 {
		_, err := get_best_stashcache(cacheListName)
		if err != nil {
			log.Errorln("Failed to get best caches:", err)
		}
	}

	// Make sure we only try as many caches as we have
	cachesToTry := 3
	if cachesToTry > len(nearest_cache_list) {
		cachesToTry = len(nearest_cache_list)
	}
	log.Debugln("Trying the caches:", nearest_cache_list[:cachesToTry])
	var transfers []TransferDetails
	url := url.URL{Path: source}
	var files []string

	if recursive {
		var err error
		files, err = walkDavDir(&url, token, namespace)
		if err != nil {
			log.Errorln("Error from walkDavDir", err)
			return err
		}
	} else {
		files = append(files, source)
	}

	// Generate all of the transfer details to make a list of transfers
	for _, cache := range nearest_cache_list[:cachesToTry] {
		// Parse the cache URL
		log.Debugln("Cache:", cache)
		transfers = append(transfers, NewTransferDetails(cache, namespace.ReadHTTPS || namespace.UseTokenOnRead)...)
	}

	// Create the wait group and the transfer files
	var wg sync.WaitGroup

	workChan := make(chan string)
	results := make(chan error, len(files))
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

	if len(results) > 0 {
		return <- results
	} else {
		return nil
	}

}

func startDownloadWorker(source string, destination string, token string, transfers []TransferDetails, wg *sync.WaitGroup, workChan <-chan string, results chan<- error) {

	defer wg.Done()
	var success bool
	for file := range workChan {
		// Remove the source from the file path
		newFile := strings.Replace(file, source, "", 1)
		finalDest := path.Join(destination, newFile)
		directory := path.Dir(finalDest)
		err := os.MkdirAll(directory, 0700)
		if err != nil {
			results <- errors.New("Failed to make directory:" + directory)
			continue
		}
		for _, transfer := range transfers {
			transfer.Url.Path = file
			log.Debugln("Constructed URL:", transfer.Url.String())
			if err := DownloadHTTP(transfer, finalDest, token); err != nil {
				log.Debugln("Failed to download:", err)
				toAccum := errors.New("Failed to download from " + transfer.Url.String() +
					" + proxy=" + strconv.FormatBool(transfer.Proxy) +
					": " + err.Error())
				AddError(toAccum)
				continue
			} else {
				success = true
				break
			}

		}
		if !success {
			log.Debugln("Failed to download with HTTP")
			results <- errors.New("failed to download with HTTP")
			return
		}
	}
}

// DownloadHTTP - Perform the actual download of the file
func DownloadHTTP(transfer TransferDetails, dest string, token string) error {

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
		req.HTTPRequest.Header.Set("Authorization", "Bearer " + token)
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
	var downloadLimit int64 = 1024 * 1024
	if downloadLimitStr != "" {
		var err error
		downloadLimit, err = strconv.ParseInt(downloadLimitStr, 10, 64)
		if err != nil {
			log.Errorln("Environment variable STASHCP_MINIMUM_DOWNLOAD_SPEED=", downloadLimitStr," is not parsable as integer:", err, "defaulting to 1MB/s")
		}
	}
	// If we are doing a recursive, decrease the download limit by the number of likely workers ~5
	if options.Recursive {
		downloadLimit /= 5
	}

	// Start the transfer
	log.Debugln("Starting the HTTP transfer...")
	filename := path.Base(dest)
	resp := client.Do(req)
	var progressBar *mpb.Bar
	if options.ProgessBars {
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
	// Loop of the download
Loop:
	for {
		select {
		case <-progressTicker.C:
			if options.ProgessBars {
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
				// Give the download 30 seconds to start
				if resp.Duration() < time.Second * 10 {
					continue
				}
				cancel()
				if options.ProgessBars {
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

				// Craft the error message
				var errorMsg = "cancelled transfer, too slow.  Detected speed: " +
					ByteCountSI(int64(resp.BytesPerSecond())) +
					"/s, total transferred: " +
					ByteCountSI(resp.BytesComplete()) +
					", total transfer time: " +
					resp.Duration().String()
				return errors.New(errorMsg)

			}

		case <-resp.Done:
			// download is complete
			if options.ProgessBars {
				var doneProgressBar = p.AddBar(resp.Size,
					mpb.BarQueueAfter(progressBar),
					mpb.BarFillerClearOnComplete(),
					mpb.PrependDecorators(
						decor.Name(filename, decor.WC{W: len(filename) + 1, C: decor.DidentRight}),
						decor.OnComplete(decor.Name(filename, decor.WCSyncSpaceR), "done!"),
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
		log.Debugln("Got error from HTTP download", err)
		return err
	}
	if resp.HTTPResponse.StatusCode != 200 {
		log.Debugln("Got failure status code:", resp.HTTPResponse.StatusCode)
		return errors.New("failure status code")
	}
	log.Debugln("HTTP Transfer was successful")
	return nil
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
func UploadFile(src string, dest *url.URL, token string, namespace Namespace) error {

	log.Debugln("In UploadFile")
	log.Debugln("Dest", dest.String())
	// Try opening the file to send
	file, err := os.Open(src)
	if err != nil {
		log.Errorln("Error opening local file:", err)
		return err
	}
	// Stat the file to get the size (for progress bar)
	fileInfo, err := file.Stat()
	if err != nil {
		log.Errorln("Error stating local file ", src, ":", err)
		return err
	}
	// Parse the writeback host as a URL
	writebackhostUrl, err := url.Parse(namespace.WriteBackHost)
	if err != nil {
		return err
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
	request, err := http.NewRequestWithContext(putContext, "PUT", dest.String(), reader)
	request.ContentLength = fileInfo.Size()
	if err != nil {
		log.Errorln("Error creating request:", err)
		return err
	}
	// Set the authorization header
	request.Header.Set("Authorization", "Bearer "+token)
	var lastKnownWritten int64
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	//log.Debug(formatRequest(request))
	go doPut(request, responseChan, errorChan)

	// Do the select on a ticker, and the writeChan
Loop:
	for {
		select {
		case <-t.C:
			// If we are not making any progress, if we haven't written 1MB in the last 5 seconds
			currentRead := atomic.LoadInt64(&reader.read)
			if lastKnownWritten < currentRead {
				// We have made progress!
				lastKnownWritten = currentRead
			} else {
				// No progress has been made in the last 1 second
				log.Errorln("No progress made in last 1 second in upload")
				break Loop
			}

		case <-closed:
			// The file has been closed, we're done here
			log.Debugln("File closed")
		case response := <-responseChan:
			log.Debugln("Received response:", response)
			break Loop

		case err := <-errorChan:
			log.Warningln("Unexpected error when performing upload:", err)
			break Loop

		}
	}

	return nil
}

// Actually perform the Put request to the server
func doPut(request *http.Request, responseChan chan<- *http.Response, errorChan chan<- error) {
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Errorln("Error with PUT:", err)
		errorChan <- err
		return
	}
	if response.StatusCode != 200 {
		log.Errorln("Error status code:", response.Status)
		log.Debugln("From the server:")
		textResponse, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Errorln("Error reading response from server:", err)
			responseChan <- response
			return
		}
		log.Debugln(string(textResponse))
	}
	responseChan <- response

}

func IsDir(url *url.URL, token string, namespace Namespace) (bool, error) {
	rootUrl := *url
	if namespace.DirListHost != "" {
		// Parse the dir list host
		dirListURL, err := url.Parse(namespace.DirListHost)
		if err != nil {
			log.Errorln("Failed to parse dirlisthost from namespaces into URL:", err)
			return false, err
		}
		rootUrl = *dirListURL

	} else {
		rootUrl.Path = ""
		rootUrl.Host = "stash.osgconnect.net:1094"
		rootUrl.Scheme = "http"
	}

	c := gowebdav.NewClient(rootUrl.String(), "", "")
	//c.SetHeader("Authorization", "Bearer "+token)

	info, err := c.Stat(url.Path)
	if err != nil {
		log.Debugln("Failed to ReadDir:", err, "for URL:", rootUrl.String())
		return false, err
	}
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
		TLSHandshakeTimeout:   15 * time.Second,
		DisableKeepAlives: true,
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