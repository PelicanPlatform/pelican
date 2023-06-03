package main

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/jessevdk/go-flags"
	stashcp "github.com/htcondor/osdf-client/v6"
	"github.com/htcondor/osdf-client/v6/classads"
	log "github.com/sirupsen/logrus"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

type Options struct {
	// Turn on the debug logging
	Debug bool `short:"d" long:"debug" description:"Turn on debug logging"`

	// Token file to use for reading and/or writing
	Token string `long:"token" short:"t" description:"Token file to use for reading and/or writing"`

	// Version information
	Version bool `long:"version" short:"v" description:"Print the version and exit"`

	// Use the hook protocol
	Hook bool `long:"hook" description:"Implement the HTCondor hook behavior"`

	// Progress bars
	ProgessBars bool `long:"progress" short:"p" description:"Show progress bars, turned on if run from a terminal"`

	// Mount prefix; e.g., /mnt/stash/ospool/osgconnect
	MountPrefix string `long:"mount" short:"m" description:"Prefix corresponding to the local mount point of the origin"`

	// Origin prefix; e.g., osdf://ospool/osgconnect
	OriginPrefix string `long:"origin-prefix" short:"o" description:"Prefix corresponding to the local origin"`

	// Shadow origin prefix; e.g., osdf://ospool/osgconnect-shadow/
	ShadowOriginPrefix string `long:"shadow-prefix" short:"s" description:"Prefix corresponding to the shadow origin" required:"true"`

	// Sources to ingest
	Sources []string `positional-arg-name:"sources" short:"i" long:"input" description:"Source file(s)" default:"-"`
}

var options Options

var parser = flags.NewParser(&options, flags.Default)

func main() {

	// Capture the start time of the transfer
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stderr, `
This utility parses a job ClassAd and, for each "osdf://" URL found in
the input files that is in a locally-mounted origin, copies the file
over to a "shadow origin".  The files in the shadow origin are given a
unique based on their last modification time; this means that local
files can be modified without causing cache consistency issues.

Terminology:
- Origin prefix: Where in the OSDF namespace the origin exports its
  files.  Example: osdf://osg-connect/protected
- Mount prefix: The location in the locally-mounted filesystem that
  correspondings to the files in the origin prefix. Example:
  /mnt/cephfs/protected
- Shadow prefix: Where in the OSDF namespace the resulting files should
  be uploaded.  Example: osdf://osg-connect-shadow/protected
`);
			os.Exit(0)
		} else {
			log.Errorln(err)
			os.Exit(1)
		}
	}

	if options.Debug {
		// Set logging to debug level
		err := setLogging(log.DebugLevel)
		if err != nil {
			log.Panicln("Failed to set logging level to Debug:", err)
		}
	} else {
		err := setLogging(log.ErrorLevel)
		if err != nil {
			log.Panicln("Failed to set logging level to Error:", err)
		}

	}

	originPrefixUri, err := url.Parse(options.OriginPrefix)
	if err != nil {
		log.Errorln("Origin prefix must be a URL (osdf://...):", err)
		os.Exit(1)
	}
	if originPrefixUri.Scheme != "osdf" {
		log.Errorln("Origin prefix scheme must be osdf://:", originPrefixUri.Scheme)
		os.Exit(1)
	}
	originPrefixPath := path.Clean("/" + originPrefixUri.Host + "/" + originPrefixUri.Path)
	log.Debugln("Local origin prefix:", originPrefixPath)

	if options.Version {
		fmt.Println("Version:", version)
		fmt.Println("Build Date:", date)
		fmt.Println("Build Commit:", commit)
		fmt.Println("Built By:", builtBy)
		os.Exit(0)
	}

	// Set the progress bars to the command line option
	stashcp.Options.ProgressBars = options.ProgessBars
	stashcp.Options.Token = options.Token

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		stashcp.Options.ProgressBars = true
	} else {
		stashcp.Options.ProgressBars = false
	}

	var sources []string
	var extraSources []string
	if options.Hook {
		buffer := make([]byte, 100*1024)
		bytesread, err := os.Stdin.Read(buffer)
		if err != nil {
			log.Errorln("Failed to read ClassAd from stdin:", err)
			os.Exit(1)
		}
		classad, err := classads.ParseClassAd(string(buffer[:bytesread]))
		if err != nil {
			log.Errorln("Failed to parse ClassAd from stdin: ", err)
			os.Exit(1)
		}
		inputList, err := classad.Get("TransferInput")
		if err != nil || inputList == nil {
			// No TransferInput, no need to transform...
			os.Exit(0)
		}
		inputListStr, ok := inputList.(string)
		if !ok {
			log.Errorln("TransferInput is not a string")
			os.Exit(1)
		}
		re := regexp.MustCompile("[,\\s]+")
		for _, source := range re.Split(inputListStr, -1) {
			log.Debugln("Examining transfer input file", source)
			if (strings.HasPrefix(source, options.MountPrefix)) {
				sources = append(sources, source)
			} else {
					// Replace the osdf:// prefix with the local mount path
				source_uri, err := url.Parse(source)
				source_uri_scheme := strings.SplitN(source_uri.Scheme, "+", 2)[0]
				if err == nil && source_uri_scheme == "osdf" {
					source_path := path.Clean("/" + source_uri.Host + "/" + source_uri.Path)
					if (strings.HasPrefix(source_path, originPrefixPath)) {
						sources = append(sources, options.MountPrefix + source_path[len(originPrefixPath):])
						continue
					}
				}
				extraSources = append(extraSources, source)
			}
		}
	} else {
		log.Debugln("Len of source:", len(options.Sources))
		if len(options.Sources) < 1 {
			log.Errorln("No ingest sources")
			parser.WriteHelp(os.Stdout)
			os.Exit(1)
		}
		sources = options.Sources
	}
	log.Debugln("Sources:", sources)

	var result error
	var xformSources []string
	for _, src := range sources {
		_, newSource, result := stashcp.DoShadowIngest(src, options.MountPrefix, options.ShadowOriginPrefix)
		if result != nil {
			// What's the correct behavior on failure?  For now, we silently put the transfer
			// back on the original list.  This is arguably the wrong approach as it might
			// give the user surprising semantics -- but keeping this until we have a bit more
			// confidence in the approach.
			extraSources = append(extraSources, src)
			log.Errorf("Failed to ingest %s: %s.  Adding original back to the transfer list",
				src, result.Error())
			continue
		}
		xformSources = append(xformSources, newSource)
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		log.Errorln(stashcp.GetErrors())
		if stashcp.ErrorsRetryable() {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}
	if options.Hook {
		inputsStr := strings.Join(extraSources, ", ")
		if len(extraSources) > 0 && len(xformSources) > 0 {
			inputsStr = inputsStr + ", " + strings.Join(xformSources, ", ")
		} else if len(xformSources) > 0 {
			inputsStr = strings.Join(xformSources, ", ")
		}
		fmt.Printf("TransferInput = \"%s\"", inputsStr)
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
