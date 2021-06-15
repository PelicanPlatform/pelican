package main

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"

	grab "github.com/cavaliercoder/grab"
	log "github.com/sirupsen/logrus"
	"github.com/studio-b12/gowebdav"
)

//var WRITEBACKHOST string = "stash-xrd.osgconnect.net:1094"

var WRITEBACKHOST string = "stash-xrd.osgconnect.net:1094"
var STASHREADABLE string = "stash.osgconnect.net:1094"

func download_http(source string, destination string, payload *payloadStruct) error {
	// Generate the url
	var downloadURL url.URL
	downloadURL.Scheme = "http"
	downloadURL.Path = source

	if len(nearest_cache_list) == 0 {
		get_best_stashcache()
	}

	log.Debugln("Trying the caches:", nearest_cache_list[:3])
	var success bool = false

	// Make sure we only try as many caches as we have
	cachesToTry := 3
	if cachesToTry > len(nearest_cache_list) {
		cachesToTry = len(nearest_cache_list)
	}
	for _, cache := range nearest_cache_list[:cachesToTry] {
		// Parse the cache URL
		cacheURL, _ := url.Parse(cache)
		downloadURL.Host = cacheURL.Host + ":8000"
		log.Debugln("Constructed URL:", downloadURL.String())
		if err := DownloadHTTP(downloadURL.String(), destination); err != nil {
			log.Debugln("Error downloading from HTTP:", err)
		} else {
			success = true
			break
		}

	}
	if success {
		return nil
	} else {
		log.Debugln("Failed to download with HTTP")
		return errors.New("failed to download with HTTP")
	}
}

// GetRedirect - Get the redirection for a URL
func DownloadHTTP(url string, dest string) error {

	// Create the client, request, and context
	client := grab.NewClient()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := grab.NewRequest(dest, url)
	req.WithContext(ctx)

	// Test the transfer speed every 5 seconds
	t := time.NewTicker(5000 * time.Millisecond)
	defer t.Stop()

	// Store the last downloaded amount, and the bottom limit of the download
	var download_limit int64 = 1024 * 1024

	// Start the transfer
	resp := client.Do(req)

	// Loop of the download
Loop:
	for {
		select {
		case <-t.C:
			// This should be made a debug logging level
			/*
				fmt.Printf("  transferred %v / %v bytes (%.2f%%) (%.2f MB/s)\n",
					resp.BytesComplete(),
					resp.Size,
					100*resp.Progress(),
					float32(resp.BytesPerSecond())/float32(1024*1024))
			*/

			// Check if we are downloading fast enough
			if resp.BytesPerSecond() < float64(download_limit) {
				// This should be warning level probably
				/*
					fmt.Printf("Cancelled transfer: transferred %v / %v bytes (%.2f%%) (%.2f MB/s)\n",
						resp.BytesComplete(),
						resp.Size,
						100*resp.Progress(),
						float32(resp.BytesPerSecond())/float32(1024*1024))
				*/
				// Cancel the transfer
				cancel()
				return errors.New("Cancelled transfer, too slow")

			}

		case <-resp.Done:
			// download is complete
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
	return nil
}

// Wrap the io.Reader to get progress
// Adapted from https://stackoverflow.com/questions/26050380/go-tracking-post-request-progress
type ProgressReader struct {
	file   *os.File
	read   int64
	size   int64
	closed chan bool
}

func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.file.Read(p)
	atomic.AddInt64(&pr.read, int64(n))
	return n, err
}

func (pr *ProgressReader) Close() error {
	err := pr.file.Close()
	// Also, send the closed channel a message
	pr.closed <- true
	return err
}

func UploadFile(src string, dest *url.URL, token string) error {

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
	dest.Host = WRITEBACKHOST
	dest.Scheme = "https"

	// Check if the destination is a directory
	isDestDir, err := IsDir(dest, token)
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
	responseChan := make(chan *http.Response)
	reader := &ProgressReader{file, 0, fileInfo.Size(), closed}
	putContext, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	go doPut(request, responseChan)
	done := false
	var doneMu sync.Mutex

	// Do the select on a ticker, and the writeChan
Loop:
	for {
		select {
		case <-t.C:
			// If we are not making any progress, if we haven't written 1MB in the last 5 seconds
			currentRead := atomic.LoadInt64(&reader.read)
			doneMu.Lock()
			realDone := done
			doneMu.Unlock()
			if realDone {
				break Loop
			}
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
			doneMu.Lock()
			done = true
			doneMu.Unlock()
			break Loop

		}
	}

	return nil
}

// Actually perform the Put request to the server
func doPut(request *http.Request, responseChan chan<- *http.Response) {
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Errorln("Error with PUT:", err)
		responseChan <- response
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

func IsDir(url *url.URL, token string) (bool, error) {
	rootUrl := *url
	rootUrl.Path = ""
	rootUrl.Host = STASHREADABLE
	rootUrl.Scheme = "http"
	c := gowebdav.NewClient(rootUrl.String(), "", "")
	//c.SetHeader("Authorization", "Bearer "+token)

	info, err := c.Stat(url.Path)
	if err != nil {
		log.Debugln("Failed to ReadDir:", err, "for URL:", rootUrl.String())
		return false, err
	}
	return info.IsDir(), nil

}
