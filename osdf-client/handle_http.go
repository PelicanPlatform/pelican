package main

import (
	"context"
	"errors"
	"net/url"
	"time"

	grab "github.com/cavaliercoder/grab"
	log "github.com/sirupsen/logrus"
)

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
	for _, cache := range nearest_cache_list[:3] {
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
