package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	stashcp "github.com/opensciencegrid/stashcp"
	"github.com/opensciencegrid/stashcp/classads"
	log "github.com/sirupsen/logrus"
)

var (
	version    = "dev"
	commit     = "none"
	date       = "unknown"
	builtBy    = "unknown"
	outputFile os.File
)

func main() {
	// Parse command line arguments
	// -classad print classad and exit
	startTime := time.Now().Unix()

	var upload bool = false
	// Set the options
	stashcp.Options.Recursive = false
	stashcp.Options.ProgressBars = false
	if err := setLogging(log.PanicLevel); err != nil {
		log.Panicln("Failed to set log level")
	}
	methods := []string{"cvmfs", "http"}
	var infile, outfile string

	// Pop the executable off the args list
	_, os.Args = os.Args[0], os.Args[1:]
	for len(os.Args) > 0 {

		if os.Args[0] == "-classad" {
			// Print classad and exit
			fmt.Println("MultipleFileSupport = true")
			fmt.Println("PluginVersion = \"" + version + "\"")
			fmt.Println("PluginType = \"FileTransfer\"")
			fmt.Println("SupportedMethods = \"stash\"")
			os.Exit(0)
		} else if os.Args[0] == "-version" || os.Args[0] == "-v" {
			fmt.Println("Version:", version)
			fmt.Println("Build Date:", date)
			fmt.Println("Build Commit:", commit)
			fmt.Println("Built By:", builtBy)
			os.Exit(0)
		} else if os.Args[0] == "-upload" {
			upload = true
		} else if os.Args[0] == "-infile" {
			infile = os.Args[1]
			os.Args = os.Args[1:]
		} else if os.Args[0] == "-outfile" {
			outfile = os.Args[1]
			os.Args = os.Args[1:]
		} else if strings.HasPrefix(os.Args[0], "-") {
			log.Errorln("Do not understand the option:", os.Args[0])
			os.Exit(1)
		} else {
			// Must be the start of a source / destination
			break
		}
		// Pop off the args
		_, os.Args = os.Args[0], os.Args[1:]
	}

	var source []string
	var dest string
	var result error
	var downloaded int64 = 0

	// Open the input and output files
	infileFile, err := os.Open(infile)
	if err != nil {
		log.Panicln("Failed to open infile:", err)
	}
	defer infileFile.Close()

	outputFile, err := os.Create(outfile)
	if err != nil {
		log.Panicln("Failed to open outfile:", err)
	}
	defer outputFile.Close()

	if len(os.Args) == 0 {
		// Read in classad from stdin
		transfers, err := readMultiTransfers(*bufio.NewReader(infileFile))
		if err != nil {
			log.Errorln("Failed to read in from stdin:", err)
			os.Exit(1)
		}
		for _, transfer := range transfers {
			var tmpDownloaded int64
			if upload {
				source = append(source, transfer.localFile)
				tmpDownloaded, result = stashcp.DoStashCPSingle(transfer.localFile, transfer.url, methods, false)
			} else {
				source = append(source, transfer.url)
				tmpDownloaded, result = stashcp.DoStashCPSingle(transfer.url, transfer.localFile, methods, false)
			}
			if result != nil {
				break
			}
			downloaded += tmpDownloaded
		}
	} else {
		source = os.Args[:len(os.Args)-1]
		dest = os.Args[len(os.Args)-1]
		for _, src := range source {
			var tmpDownloaded int64
			tmpDownloaded, result = stashcp.DoStashCPSingle(src, dest, methods, false)
			downloaded += tmpDownloaded
			if result != nil {
				break
			}
		}
	}

	fmt.Fprintln(outputFile, "TransferStartTime = ", startTime)
	fmt.Fprintln(outputFile, "TransferEndTime = ", time.Now().Unix())
	hostname, _ := os.Hostname()
	//if err != nil {
	//	log.Errorln("Error getting hostname: ", err)
	//}
	fmt.Fprintln(outputFile, "TransferLocalMachineName = \"", hostname, "\"")
	fmt.Fprintln(outputFile, "TransferProtocol = \"stash\"")
	fmt.Fprint(outputFile, "TransferUrl = \"", source[0], "\"", "\n")
	fmt.Fprintln(outputFile, "TransferType = \"download\"")
	if result != nil {
		fmt.Fprintln(outputFile, "TransferSuccess = false")
		fmt.Fprint(outputFile, "TransferError = \"", stashcp.GetErrors(), "\"", "\n")
		fmt.Fprintln(outputFile, "TransferFileBytes = 0")
		fmt.Fprintln(outputFile, "TransferTotalBytes = 0")
		if stashcp.ErrorsRetryable() {
			fmt.Fprintln(outputFile, "TransferRetryable = true")
			os.Exit(11)
		} else {
			fmt.Fprintln(outputFile, "TransferRetryable = false")
			os.Exit(1)
		}
	} else {
		// Stat the destination file
		fmt.Fprintln(outputFile, "TransferSuccess = true")
		fmt.Fprintln(outputFile, "TransferFileBytes =", downloaded)
		fmt.Fprintln(outputFile, "TransferTotalBytes =", downloaded)
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
	url       string
	localFile string
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
		transfers = append(transfers, Transfer{url: url.(string), localFile: destination.(string)})
	}

	return transfers, nil
}
