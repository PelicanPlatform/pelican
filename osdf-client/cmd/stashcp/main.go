package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	stashcp "github.com/htcondor/osdf-client/v6"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

type SourceDestination struct {
	Sources []string `positional-arg-name:"sources" short:"i" long:"input" description:"Source file(s)" default:"-"`

	// A useless variable.  It should alwasy be empty.  The Sources variable above should "grab" all of the positional arguments
	// The only reason we have this variable is so the help message has the [sources...] [destination] help mesage.
	Destination string `positional-arg-name:"destination" short:"o" long:"output" description:"Destination file/directory" default:"-"`
}

type Options struct {
	// Turn on the debug logging
	Debug bool `short:"d" long:"debug" description:"Turn on debug logging"`

	// Specify the configuration file
	Closest bool `long:"closest" description:"Return the closest cache and exit"`

	// Cache to use
	Cache string `short:"c" long:"cache" description:"Cache to use"`

	// A JSON file containing the list of caches
	CacheJSON string `short:"j" long:"caches-json" description:"A JSON file containing the list of caches"`

	// Comma separated list of methods to try, in order.  Default: cvmfs,http
	Methods string `long:"methods" description:"Comma separated list of methods to try, in order." default:"cvmfs,http"`

	// Token file to use for reading and/or writing
	Token string `long:"token" short:"t" description:"Token file to use for reading and/or writing"`

	ListCaches bool `long:"list-names" description:"Return the names of pre-configured cache lists and exit"`

	ListDir bool `long:"list-dir" short:"l" description:"List the directory pointed to by source"`

	// Version information
	Version bool `long:"version" short:"v" description:"Print the version and exit"`

	// Namespace information
	PrintNamespaces bool `long:"namespaces" description:"Print the namespace information and exit"`

	// List Types (xroot or xroots)
	ListType string `long:"cache-list-name" short:"n" description:"Cache list to use, currently either xroot or xroots" default:"xroot"`

	// Recursive walking of directories
	Recursive bool `short:"r" description:"Recursively copy a directory.  Forces methods to only be http to get the freshest directory contents"`

	// Progress bars
	ProgessBars bool `long:"progress" short:"p" description:"Show progress bars, turned on if run from a terminal"`

	// PluginInterface specifies how the output should be formatted
	PluginInterface bool `long:"plugininterface" description:"Output in HTCondor plugin format.  Turned on if executable is named stash_plugin"`

	// Positional arguemnts
	SourceDestination SourceDestination `description:"Source and Destination Files" positional-args:"1"`
}

var options Options

var parser = flags.NewParser(&options, flags.Default)

func main() {

	stashcp.Options.Version = version
	
	// Capture the start time of the transfer
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
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

	if options.PrintNamespaces {
		namespaces, err := stashcp.GetNamespaces()
		if err != nil {
			fmt.Println("Failed to get namespaces:", err)
			os.Exit(1)
		}
		fmt.Printf("%+v\n", namespaces)
		os.Exit(0)
	}

	// Just return all the caches that it knows about
	// Print out all of the caches and exit
	if options.ListCaches {
		cacheList, err := stashcp.GetBestCache(options.ListType)
		if err != nil {
			log.Errorln("Failed to get best caches:", err)
			os.Exit(1)
		}
		// Print the caches, comma separated,
		fmt.Println(strings.Join(cacheList[:], ","))
		os.Exit(0)
	}

	if options.Closest {
		cacheList, err := stashcp.GetBestCache(options.ListType)
		if err != nil {
			log.Errorln("Failed to get best stashcache: ", err)
		}
		fmt.Println(cacheList[0])
		os.Exit(0)
	}

	log.Debugln("Len of source:", len(options.SourceDestination.Sources))
	if len(options.SourceDestination.Sources) < 2 {
		log.Errorln("No Source or Destination")
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}
	source := options.SourceDestination.Sources[:len(options.SourceDestination.Sources)-1]
	dest := options.SourceDestination.Sources[len(options.SourceDestination.Sources)-1]

	log.Debugln("Sources:", source)
	log.Debugln("Destination:", dest)
	if options.ListDir {
		dirUrl, _ := url.Parse("http://stash.osgconnect.net:1094")
		dirUrl.Path = source[0]
		isDir, err := stashcp.IsDir(dirUrl, "", stashcp.Namespace{})
		if err != nil {
			log.Errorln("Error getting directory listing:", err)
		}
		log.Debugln("Dir is a directory?", isDir)
		return
	}

	/*
		TODO: Parse a caches JSON, is this needed anymore?
		if args.caches_json {
			caches_json_location = caches_json

		} else if val, jsonPresent := os.LookupEnv("CACHES_JSON"); jsonPresent {
			caches_json_location = val
		} else {
			prefix = os.Getenv("OSG_LOCATION", "/")
			caches_file = filepath.Join(prefix, "etc/stashcache/caches.json")
			if _, err := os.Stat(caches_file); err == nil {
				caches_json_location = caches_file
			}
		}

		caches_list_name = args.cache_list_name
	*/

	// Check for manually entered cache to use ??
	nearestCache, nearestCacheIsPresent := os.LookupEnv("NEAREST_CACHE")

	if nearestCacheIsPresent {
		stashcp.NearestCache = nearestCache
		stashcp.NearestCacheList = append(stashcp.NearestCacheList, stashcp.NearestCache)
		stashcp.CacheOverride = true
	} else if options.Cache != "" {
		stashcp.NearestCache = options.Cache
		stashcp.NearestCacheList = append(stashcp.NearestCacheList, options.Cache)
		stashcp.CacheOverride = true
	}

	// Convert the methods
	splitMethods := strings.Split(options.Methods, ",")

	// If the user overrides the cache, then only use HTTP
	if stashcp.CacheOverride {
		splitMethods = []string{"http"}
	}

	if len(source) > 1 {
		if destStat, err := os.Stat(dest); err != nil && destStat.IsDir() {
			log.Errorln("Destination is not a directory")
			os.Exit(1)
		}
	}

	var result error
	var downloaded int64 = 0
	lastSrc := ""
	for _, src := range source {
		var tmpDownloaded int64
		tmpDownloaded, result = stashcp.DoStashCPSingle(src, dest, splitMethods, options.Recursive)
		downloaded += tmpDownloaded
		if result != nil {
			lastSrc = src
			break
		} else {
			stashcp.ClearErrors()
		}
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		errMsg := stashcp.GetErrors()
		if errMsg == "" {
			errMsg = result.Error()
		}
		log.Errorln("Failure downloading " + lastSrc + ": " + errMsg)
		if stashcp.ErrorsRetryable() {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
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
