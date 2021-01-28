package main

import (
	"context"
	"errors"
	"time"

	// curl "github.com/andelf/go-curl"
	grab "github.com/cavaliercoder/grab"
)

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
	return nil
}
