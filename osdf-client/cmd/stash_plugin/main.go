package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"time"

	stashcp "github.com/opensciencegrid/stashcp"
	"github.com/opensciencegrid/stashcp/classads"
	log "github.com/sirupsen/logrus"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	// Parse command line arguments
	// -classad print classad and exit
	startTime := time.Now().Unix()

	for _, arg := range os.Args[1:] {
		if arg == "-classad" {
			// Print classad and exit
			fmt.Println("MultipleFileSupport = true")
			fmt.Println("PluginVersion = \"" + version + "\"")
			fmt.Println("PluginType = \"FileTransfer\"")
			fmt.Println("SupportedMethods = \"stash\"")
			os.Exit(0)
		} else if arg == "-version" || arg == "-v" {
			fmt.Println("Version:", version)
			fmt.Println("Build Date:", date)
			fmt.Println("Build Commit:", commit)
			fmt.Println("Built By:", builtBy)
			os.Exit(0)
		}
	}
	

	source := os.Args[:len(os.Args)-1]
	dest := os.Args[len(os.Args)-1]
	methods := []string{"cvmfs", "http"}
	setLogging(log.PanicLevel)

	// Set the options
	stashcp.Options.Recursive = false
	stashcp.Options.ProgressBars = false

	var result error
	var downloaded int64 = 0
	for _, src := range source {
		var tmpDownloaded int64
		tmpDownloaded, result = stashcp.DoStashCPSingle(src, dest, methods, false)
		downloaded += tmpDownloaded
		if result != nil {
			break
		}
	}

	fmt.Print("TransferStartTime = ", startTime, "\n")
	fmt.Print("TransferEndTime = ", time.Now().Unix(), "\n")
	hostname, _ := os.Hostname()
	//if err != nil {
	//	log.Errorln("Error getting hostname: ", err)
	//}
	fmt.Print("TransferLocalMachineName = \"", hostname, "\"", "\n")
	fmt.Println("TransferProtocol = \"stash\"")
	fmt.Print("TransferUrl = \"", source[0], "\"", "\n")
	fmt.Println("TransferType = \"download\"")
	if result != nil {
		fmt.Println("TransferSuccess = false")
		fmt.Print("TransferError = \"", stashcp.GetErrors(), "\"", "\n")
		fmt.Println("TransferFileBytes = 0")
		fmt.Println("TransferTotalBytes = 0")
		if stashcp.ErrorsRetryable() {
			fmt.Println("TransferRetryable = true")
			os.Exit(11)
		} else {
			fmt.Println("TransferRetryable = false")
			os.Exit(1)
		}
	} else {
		// Stat the destination file
		fmt.Println("TransferSuccess = true")
		fmt.Print("TransferFileBytes = ", downloaded, "\n")
		fmt.Print("TransferTotalBytes = ", downloaded, "\n")
	}

}

func setLogging(logLevel log.Level) error {
	textFormatter := log.TextFormatter{}
	textFormatter.DisableLevelTruncation = true
	textFormatter.FullTimestamp = true
	log.SetFormatter(&textFormatter)
	log.SetLevel(logLevel)
	return nil
}

type Transfer struct {
	source      string
	destination string
}

// readMultiTransfers reads the transfers from a Reader, such as stdin
func readMultiTransfers(stdin bufio.Reader) (transfers []Transfer, err error) {
	// Check stdin for a list of transfers
	ads, err := classads.ReadClassAd(&stdin)
	if err != nil {
		return nil, err
	}
	if ads == nil {
		return nil, errors.New("No transfers found")
	}
	for _, ad := range ads {
		url, err := ad.Get("Url")
		if err != nil {
			return nil, err
		}
		destination, err := ad.Get("LocalFileName")
		if err != nil {
			return nil, err
		}
		transfers = append(transfers, Transfer{url.(string), destination.(string)})
	}

	return transfers, nil
}



