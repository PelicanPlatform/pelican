package main

import (
	"syscall"
	"flag"
	"fmt"
	"net/url"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"math/rand"
	"strings"
	lumber "github.com/jcelliott/lumber"
)

// Redirector
var global_redirector string = "http://redirector.osgstorage.org:8000"
var cache_host string = "http://hcc-stash.unl.edu:8000/"
var VERSION string = "5.6.2"

var nearest_cache string
var nearest_cache_list string
var caches_json_location string

func main() {

	// Basic flag declarations are available for string,
	// integer, and boolean options. Here we declare a
	// string flag `word` with a default value `"foo"`
	// and a short description. This `flag.String` function
	// returns a string pointer (not a string value);
	// we'll see how to use this pointer below.
	//wordPtr := flag.String("cache", "", "The cache to use")
	//debug := flag.Bool("debug", false, "Debug output")

	// This declares `numb` and `fork` flags, using a
	// similar approach to the `word` flag.
	//numbPtr := flag.Int("numb", 42, "an int")
	//boolPtr := flag.Bool("fork", false, "a bool")

	// It's also possible to declare an option that uses an
	// existing var declared elsewhere in the program.
	// Note that we need to pass in a pointer to the flag
	// declaration function.
	//var svar string
	//flag.StringVar(&svar, "svar", "bar", "a string var")

	// Once all flags are declared, call `flag.Parse()`
	// to execute the command-line parsing.
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Printf("Must have at least 2 arguments\n")
		os.Exit(1)
	}
	source := args[0]
	dest := args[1]

	// Combine the paths
	srcURL, _ := url.Parse(cache_host)
	srcURL.Path = path.Join(srcURL.Path, source)

	// get absolute path
	destPath, _ := filepath.Abs(dest)
	var destFinal string

	//Check if path exists or if its in a folder
	if destStat, err := os.Stat(destPath); os.IsNotExist(err) {
		fmt.Println("file does not exist")
		destFinal = destPath
	} else if destStat.IsDir() {
		// Get the file name of the source
		sourceFilename := path.Base(source)
		destFinal = path.Join(destPath, sourceFilename)
	}

	// fmt.Printf("url=" + srcURL.String() + " dest=" + destFinal + "\n")
	// if err := DownloadHTTP(srcURL.String(), destFinal); err != nil {
	// 	fmt.Printf("Download failed")
	// }

	payload := payloadStruct{tries: 0, cache: "", host: ""}

	download_cvmfs(srcURL.String(), destFinal, payload)

	//fmt.Printf("Trying URL: %v\n", u.String())
	//redir := GetRedirect(u.String())
	//fmt.Printf("ERROR: %v\n", redir)

	// Started Here

	/*

			userAgent := "stashcp/" + VERSION

			main_redirector := "root://redirector.osgstorage.org"
			stash_origin := "root://stash.osgconnect.net"
			writeback_host := "http://stash-xrd.osgconnect.net:1094"

		//Global variable for nearest cache
			nearest_cache :=  ""// ?? what type

		// Ordered list of nearest caches  ***************************************
			nearest_cache_list := []int{}

		// Global variable for the location of the caches.json file
			caches_json_location := ""

		// Global variable for the name of a pre-configured cache list
			cache_list_name := ""

		// Global variable for the location of the token to use for reading / writing
			token_location := ""

		// Global variable to print names of cache lists
			print_cache_list_names := ""

			TIMEOUT := 300
			DIFF    := TIMEOUT * 10

	*/

}

func doWriteBack(source string, destination string, debug bool) /*unsure of return type*/ {
	/*
			  Do a write back to Stash using SciTokens

		    :param str source: The location of the local file
		    :param str destination: The location of the remote file, in stash:// format
	*/

	//start1 := int(time.Now()*1000)
	/*
		scitoken_contents := ""//getToken()
		if scitoken_contents == getToken() {
			errors.New("Unable to find scitokens.use file")
			return
		}

		if debug == true {
			output_mode := "-v"
		} else {
			output_mode := "-s"
		}
	*/
	/* Commented out for now

	//Check if the source file is zero-length
	statinfo := os.Stat(source)

	if statinfo.Size() == 0 {  //CHECK After rsoolving compilation error Size method should be in OS or Syscall
		speed_time = "--speed-time 5 "
	} else {
		speed_time := ""
	}
	command := fmt.Sprintf("curl %s --connect-timeout 30 %s--speed-limit 1024 -X PUT --fail --upload-file %s -H \"User-Agent: %s\" -H \"Authorization: Bearer %s\" %s%s",output_mode, speed_time, source, user_agent, scitoken_contents, writeback_host, destination)

	val, present := os.LookupEnv("http_proxy")
	if present { // replace with go in method
		(os.Environ).Clearenv()
	}
	*/

}

func getToken() string {
	// Get the token / scitoken from the environment in order to read/write

	// Get the scitoken content
	//scitoken_file := ""

	/*
		// command line
		if token_location {
			scitoken_file = token_location
		}
	*/

	//if 'TOKEN'
	return ""
}

func get_best_stashcache() {
	var nearest_cache_list string

	// Use the geo ip service on the WLCG Web Proxy Auto Discovery machines
	geo_ip_sites := [...]string{"wlcg-wpad.cern.ch", "wlcg-wpad.fnal.gov"}

	 
    //# Headers for the HTTP request
	
	req.Header.set("Cache-control", "max-age=0")
	req.Header.set("User-Agent", "user_agent")
	
	// randomize the geo ip sites
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(geo_ip_sites), func(i, j int){
		geo_ip_sites[i], geo_ip_sites[j] = geo_ip_sites[j], geo_ip_sites[i]
	})


	var api_text string = ""

	//caches_list := []

	
	// Check if the user provided a caches json file location
	if caches_json_location != nil {
		if _, err := os.Stat(caches_json_location); os.IsNotExist(err) {
			// path does not exist
			log := lumber.NewConsoleLogger(lumber.WARN)
			log.Error(caches_json_location + " does not exist")
			
			return nil
		  }

		  //Use geo ip api on caches in provided json file
		  caches_list := get_json_caches(caches_json_location)
		  var caches_string string = ""
		
		  for _,cache := range caches_list {
			  parsed_url, err := url.Parse(s)
			  if err != nil {
				  log.Error("Could not parse URL")
			  }
			  
			  caches_string = caches_string + parsed_url.hostname

			  // Remove the first comma
			  caches_string = string([]rune(caches_string)[1:])
			  api_text = "api/v1.0/geo/stashcp/" + caches_string
		  }
	} else {
		//Use Stashservers.dat api

		api_text = "stashservers.dat"
		if cache_list_name != nil {
			api_text = api_text + "?list=" + cache_list_name
		}
	}

	var responselines_b []string

	type header struct {
		Host string		
	}

	var i int = 0

	for len(responselines_b) == 0 ; i < len(geo_ip_sites); i++{

		cur_site := geo_ip_sites[i]
		var headers header
		headers.Host = cur_site
		log.Debug("Trying server site of %s", cur_site)
		
		for _, ip := range get_ips(cur_site) {
			final_url := "http://" + ip + api_text
			log.Debug("Querying"+ final_url)

			// Make the request
			req := requests.get(final_url, headers==headers)
			resp, err := http.Get(final_url)
			if err != nil {
				log.Error("Could not open URL")
			}

			if resp.StatusCode == 200 {
				log.Debug("Got OK code 200 from %s", cur_site)
				responsetext_b := resp
				responsetext_b, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Error("Could not aquire http response text")
				}
				strings.Split(responsetext_b,"/n")
				defer resp.Body.Close()
			} 
		}
	
	}
	order_str := ""
	
	if len(responselines_b) > 0 {
		order_str = string(responselines_b[0])
	} 

	if order_str == "" {
		if len(caches_list) == 0 {
			log.Error("unable to get list of caches")
			return nil
		}
		//Unable to find a geo_ip server to user, return random choice from caches
		nearest_cache_list = cache_list
		rand.Shuffle(len(nearest_cache_list), func(i, j string) { nearest_cache_list[i], nearest_cache_list[j] = nearest_cache_list[j], nearest_cache_list[i] })
		minsite := nearest_cache_list[0]
		log.Debug("Unable to use Geoip to find closest cache!  Returning random cache %s", minsite)
		log.Debug("Randomized list of nearest caches: %s", str(nearest_cache_list))
		return minsite
	} else{
		// The order string should be something like: 3,1,2
		
		ordered_list := strings.Trim(order_str)
		strings.Split(ordered_list, ",")

		if len(caches_list) == 0 {
			//Used the stashservers.dat api
			caches_list = get_stashservers_caches(responselines_b)

			if caches_list == nil {
				return nil
			}
		}

		minsite = caches_list[int(ordered_list[0])-1]

		var nearest_cache []string 

		for _,ordered_index := range ordered_list {
			nearest_cache_list = append(caches_list[int(ordered_index)-1])	
		}

        log.Debug("Returning closest cache: %s", minsite)
        log.Debug("Ordered list of nearest caches: %s", string(nearest_cache_list))
        return minsite
	}
}


// Return list of cache URLS
func get_json_caches(caches_json_location) []string {
	
	log := lumber.NewConsoleLogger(lumber.WARN)

	type cachesListMap struct {
		status string
		name  int
	}
	
	// myMap := map[int][]cachesListMap{}
			
	f, _ := ioutil.ReadFile(filename)
	var caches_list cachesListMap
	err := json.Unmarshal(f, &caches_list)

	if err != nil{		
		log.Error("No cache names found in %s without zero status", caches_json_location)
	}
	
	log.Debug("Loaded caches list from %s", caches_json_location)

	usable_caches := []string{}

	for _,cache := range caches_list {
		if caches_list.status == 0 {
			usable_caches = append(usable_caches, caches_list.name)
		}	
	}

	if len(usable_caches) == 0 {
		log.Error("No cache names found in %s without zero status", caches_json_location)
	}

	return usable_caches
		
}

func get_ips(name) {
	var ipv4s []string 
	
	var ipv6s []string 
	
	log := lumber.NewConsoleLogger(lumber.WARN)

	info, err := net.LookupHost(name)
	if err != nil {
		log.Error("Unable to look up %s", name)
		return []string
	}

	for _,tuple := range info {
	
		if tuple[0] == syscall.AF_INET {
			ipv4s = append(ipv4s, tuple[4][0])
		} else if tuple[0] == syscall.AF_INET6 {
			ipv6s = append(ipv4s, tuple[4][0])
		}	
	}
	
	//Randomize the order of each
	rand.Shuffle(len(ipv4s), func(i, j string) { ipv4s[i], ipv4s[j] = ipv4s[j], ipv4s[i] })
	rand.Shuffle(len(ipv6s), func(i, j string) { ipv6s[i], ipv6s[j] = ipv6s[j], ipv6s[i] })

	// Always prefer IPv4
	return ipv4s + ipv6s

	}

