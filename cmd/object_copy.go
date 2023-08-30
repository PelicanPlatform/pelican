package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelicanplatform/pelican"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespaces"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	copyCmd = &cobra.Command{
		Use:   "copy {source ...} {destination}",
		Short: "Copy a file to/from a Pelican federation",
		Run:   copyMain,
	}
)

func init() {
	exec_name := filepath.Base(os.Args[0])
	flagSet := copyCmd.Flags()
	flagSet.StringP("cache", "c", "", "Cache to use")
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively copy a directory.  Forces methods to only be http to get the freshest directory contents")
	flagSet.StringP("cache-list-name", "n", "xroot", "(Deprecated) Cache list to use, currently either xroot or xroots; may be ignored")
	flagSet.Lookup("cache-list-name").Hidden = true
	// All the deprecated or hidden flags that are only relevant if we are in historical "stashcp mode"
	if exec_name == "stashcp" {
		copyCmd.Use = "stashcp {source ...} {destination}"
		copyCmd.Short = "Copy a file to/from the OSDF"
		flagSet.Lookup("cache-list-name").Hidden = false // Expose the help for this option
		flagSet.StringP("caches-json", "j", "", "A JSON file containing the list of caches")
		flagSet.Bool("closest", false, "Return the closest cache and exit")
		flagSet.BoolP("debug", "d", false, "Enable debug logs") // Typically set by the root command (which doesn't exist in stashcp mode)
		flagSet.Bool("list-names", false, "Return the names of pre-configured cache lists and exit")
		flagSet.String("methods", "cvmfs,http", "Comma separated list of methods to try, in order")
		flagSet.Bool("namespaces", false, "Print the namespace information and exit")
		flagSet.Bool("plugininterface", false, "Output in HTCondor plugin format.  Turned on if executable is named stash_plugin")
		flagSet.Lookup("plugininterface").Hidden = true // This has been a no-op for quite some time.
		flagSet.BoolP("progress", "p", false, "Show progress bars, turned on if run from a terminal")
		flagSet.Lookup("progress").Hidden = true // This has been a no-op for quite some time.
		flagSet.BoolP("version", "v", false, "Print the version and exit")
	} else {
		flagSet.String("caches", "", "A JSON file containing the list of caches")
		flagSet.String("methods", "http", "Comma separated list of methods to try, in order")
		objectCmd.AddCommand(copyCmd)
	}
}

func copyMain(cmd *cobra.Command, args []string) {

	pelican.ObjectClientOptions.Version = version

	if val, err := cmd.Flags().GetBool("debug"); err == nil && val {
		setLogging(log.DebugLevel)
	} else {
		setLogging(log.ErrorLevel)
	}

	err := config.InitClient()
	if err != nil {
		log.Errorln(err)
		os.Exit(1)
	}

	if val, err := cmd.Flags().GetBool("version"); err == nil && val {
		fmt.Println("Version:", version)
		fmt.Println("Build Date:", date)
		fmt.Println("Build Commit:", commit)
		fmt.Println("Built By:", builtBy)
		os.Exit(0)
	}

	// Set the progress bars to the command line option
	pelican.ObjectClientOptions.Token, _ = cmd.Flags().GetString("token")

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		pelican.ObjectClientOptions.ProgressBars = true
	} else {
		pelican.ObjectClientOptions.ProgressBars = false
	}

	if val, err := cmd.Flags().GetBool("namespaces"); err == nil && val {
		namespaces, err := namespaces.GetNamespaces()
		if err != nil {
			fmt.Println("Failed to get namespaces:", err)
			os.Exit(1)
		}
		fmt.Printf("%+v\n", namespaces)
		os.Exit(0)
	}

	// Just return all the caches that it knows about
	// Print out all of the caches and exit
	if val, err := cmd.Flags().GetBool("list-names"); err == nil && val {
		listName, _ := cmd.Flags().GetString("cache-list-name")
		cacheList, err := pelican.GetBestCache(listName)
		if err != nil {
			log.Errorln("Failed to get best caches:", err)
			os.Exit(1)
		}
		// Print the caches, comma separated,
		fmt.Println(strings.Join(cacheList[:], ","))
		os.Exit(0)
	}

	if val, err := cmd.Flags().GetBool("closest"); err == nil && val {
		listName, err := cmd.Flags().GetString("cache-list-name")
		if err != nil {
			log.Errorln("Failed to determine correct cache list")
			os.Exit(1)
		}
		cacheList, err := pelican.GetBestCache(listName)
		if err != nil {
			log.Errorln("Failed to get best cache: ", err)
		}
		fmt.Println(cacheList[0])
		os.Exit(0)
	}

	log.Debugln("Len of source:", len(args))
	if len(args) < 2 {
		log.Errorln("No Source or Destination")
		err = cmd.Help()
		if err != nil {
			log.Errorln("Failed to print out help:", err)
		}
		os.Exit(1)
	}
	source := args[:len(args)-1]
	dest := args[len(args)-1]

	log.Debugln("Sources:", source)
	log.Debugln("Destination:", dest)

	// Check for manually entered cache to use ??
	nearestCache, nearestCacheIsPresent := os.LookupEnv("NEAREST_CACHE")

	if nearestCacheIsPresent {
		pelican.NearestCache = nearestCache
		pelican.NearestCacheList = append(pelican.NearestCacheList, pelican.NearestCache)
		pelican.CacheOverride = true
	} else if cache, _ := cmd.Flags().GetString("cache"); cache != "" {
		pelican.NearestCache = cache
		pelican.NearestCacheList = append(pelican.NearestCacheList, cache)
		pelican.CacheOverride = true
	}

	// Convert the methods
	methodNames, _ := cmd.Flags().GetString("methods")
	splitMethods := strings.Split(methodNames, ",")

	// If the user overrides the cache, then only use HTTP
	if pelican.CacheOverride {
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
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		tmpDownloaded, result = pelican.DoStashCPSingle(src, dest, splitMethods, isRecursive)
		downloaded += tmpDownloaded
		if result != nil {
			lastSrc = src
			break
		} else {
			pelican.ClearErrors()
		}
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		errMsg := pelican.GetErrors()
		if errMsg == "" {
			errMsg = result.Error()
		}
		log.Errorln("Failure downloading " + lastSrc + ": " + errMsg)
		if pelican.ErrorsRetryable() {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

}
