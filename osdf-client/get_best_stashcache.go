package main

import (
	"errors"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	lumber "github.com/jcelliott/lumber"
)

func get_best_stashcache() (string, error) {

	log := lumber.NewConsoleLogger(lumber.WARN)

	// Use the geo ip service on the WLCG Web Proxy Auto Discovery machines
	geo_ip_sites := [...]string{"wlcg-wpad.cern.ch", "wlcg-wpad.fnal.gov"}

	// randomize the geo ip sitess
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(geo_ip_sites), func(i, j int) {
		geo_ip_sites[i], geo_ip_sites[j] = geo_ip_sites[j], geo_ip_sites[i]
	})

	var api_text string = ""

	var caches_list []string

	// Check if the user provided a caches json file location
	if caches_json_location != "" {
		if _, err := os.Stat(caches_json_location); os.IsNotExist(err) {
			// path does not exist
			log := lumber.NewConsoleLogger(lumber.WARN)
			log.Error(caches_json_location + " does not exist")

			return "", errors.New("Unable to open caches json file at: " + caches_json_location)
		}

		//Use geo ip api on caches in provided json file
		caches_list := get_json_caches(caches_json_location)
		var caches_string string = ""

		for _, cache := range caches_list {
			parsed_url, err := url.Parse(cache)
			if err != nil {
				log.Error("Could not parse URL")
			}

			caches_string = caches_string + parsed_url.Host

			// Remove the first comma
			caches_string = string([]rune(caches_string)[1:])
			api_text = "api/v1.0/geo/stashcp/" + caches_string
		}
	} else {
		//Use Stashservers.dat api

		api_text = "stashservers.dat"
		if caches_list_name != "" {
			api_text = api_text + "?list=" + caches_list_name
		}
	}

	var responselines_s []string

	type header struct {
		Host string
	}

	var i int = 0

	for i = 0; i < len(geo_ip_sites); i++ {

		cur_site := geo_ip_sites[i]
		var headers header
		headers.Host = cur_site
		log.Debug("Trying server site of %s", cur_site)

		for _, ip := range get_ips(cur_site) {
			final_url := "http://" + ip + api_text
			log.Debug("Querying" + final_url)

			// Headers for the HTTP request
			// Create an HTTP client
			client := &http.Client{}
			req, err := http.NewRequest("GET", final_url, nil)
			req.Header.Add("Cache-control", "max-age=0")
			req.Header.Add("User-Agent", "user_agent")
			resp, err := client.Do(req)
			if err != nil {
				log.Error("Could not open URL")
			}

			if resp.StatusCode == 200 {
				log.Debug("Got OK code 200 from %s", cur_site)
				responsetext_b, err := ioutil.ReadAll(resp.Body)
				responsetext_s := string(responsetext_b)
				responselines_s = strings.Split(responsetext_s, "/n")
				if err != nil {
					log.Error("Could not aquire http response text")
				}
				strings.Split(responsetext_s, "/n")
				defer resp.Body.Close()
				break
			}
		}

		// If we got a response, then stop trying other geoip servers
		if len(responselines_s) > 0 {
			break
		}

	}
	order_str := ""

	if len(responselines_s) > 0 {
		order_str = string(responselines_s[0])
	}

	if order_str == "" {
		if len(caches_list) == 0 {
			log.Error("unable to get list of caches")
			return "", errors.New("Unable to get the list of caches")
		}
		//Unable to find a geo_ip server to user, return random choice from caches
		nearest_cache_list = caches_list
		rand.Shuffle(len(nearest_cache_list), func(i, j int) {
			nearest_cache_list[i], nearest_cache_list[j] = nearest_cache_list[j], nearest_cache_list[i]
		})
		minsite := nearest_cache_list[0]
		log.Debug("Unable to use Geoip to find closest cache!  Returning random cache %s", minsite)
		log.Debug("Randomized list of nearest caches: %s", strings.Join(nearest_cache_list, ","))
		return minsite, nil
	} else {
		// The order string should be something like: 3,1,2

		ordered_list := strings.Trim(order_str)
		strings.Split(ordered_list, ",")

		if len(caches_list) == 0 {
			//Used the stashservers.dat api
			caches_list = get_stashservers_caches(responselines_s)

			if caches_list == nil {
				return nil
			}
		}

		minsite = caches_list[int(ordered_list[0])-1]

		var nearest_cache []string

		for _, ordered_index := range ordered_list {
			nearest_cache_list = append(caches_list[int(ordered_index)-1])
		}

		log.Debug("Returning closest cache: %s", minsite)
		log.Debug("Ordered list of nearest caches: %s", string(nearest_cache_list))
		return minsite
	}
}
