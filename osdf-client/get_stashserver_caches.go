package main

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	lumber "github.com/jcelliott/lumber"
)

func get_stashservers_caches(responselines_b []string) []string {

	/**
		 After the geo order of the selected server list on line zero,
	      the rest of the response is in .cvmfswhitelist format.
	     This is done to avoid using https for every request on the
	      wlcg-wpad servers and takes advantage of conveniently
	      existing infrastructure.
	     The format contains the following lines:
	     1. Creation date stamp, e.g. 20200414170005.  For debugging
	        only.
	     2. Expiration date stamp, e.g. E20200421170005.  cvmfs clients
	        check this to avoid replay attacks, but for this api that
	        is not much of a risk so it is ignored.
	     3. "Repository" name, e.g. Nstash-servers.  cvmfs clients
	        also check this but it is not important here.
	     4. With cvmfs the 4th line has a repository fingerprint, but
	        for this api it instead contains a semi-colon separated list
	        of named server lists.  Each server list is of the form
	        name=servers where servers is comma-separated.  Ends with
	        "hash=-sha1" because cvmfs_server expects the hash name
	        to be there.  e.g.
	        xroot=stashcache.t2.ucsd.edu,sg-gftp.pace.gatech.edu;xroots=xrootd-local.unl.edu,stashcache.t2.ucsd.edu;hash=-sha1
	     5. A two-dash separator, i.e "--"
	     6. The sha1 hash of lines 1 through 4.
	     7. The signature, i.e. an RSA encryption of the hash that can
	        be decrypted by the OSG cvmfs public key.  Contains binary
	        information so it may contain a variable number of newlines
	        which would have caused it to have been split into multiple
		    response "lines".
		**/
	log := lumber.NewConsoleLogger(lumber.WARN)

	if len(responselines_b) < 8 {

		log.Error("stashservers response too short, less than 8 lines")
		return []string{}, errors.New("stashservers response too short, less than 8 lines")
	}

	// Get the 5th row (4th index), the last 5 characters
	hashname_b := responselines_b[4][len(responselines_b[4])-5:]

	if hashname_b != "-sha1" {

		log.Error("stashservers response does not have sha1 hash: %s", string(hashname_b))
		return []string{}, errors.New("stashservers response does not have sha1 hash: %s", hashname_b)
	}

	var hashedTextBuilder strings.Builder
	// Loop through response lines 1 through 4
	for i := 1; i < 5; i++ {
		hashedTextBuilder.WriteString(responselines_b[i])
		hashedTextBuilder.WriteString("\n")
	}
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(hashedTextBuilder.String()))
	hashStr := hex.EncodeToString(sha1Hash.Sum(nil))

	if string(responselines_b[6]) != hashStr {
		log.Debug("stashservers hash %s does not match expected hash %s", string(responselines_b[6]), hash_str)
		log.Debug("hashed text:\n%s", string(hashedtext_b))
		log.Error("stashservers response hash does not match expected hash")
		return nil
	}

	// Call out to /usr/bin/openssl if present, in order to avoid
	// python dependency on a crypto package.

	if destStat, err := os.Stat("/usr/bin/openssl"); os.IsNotExist(err) {
		// The signature check isn't critical to be done everywhere;
		// any tampering will likely to be caught somewhere and
		// investigated.  Usually openssl is present.
		log.Debug("openssl not installed, skipping signature check")
	} else {
		sig := responselines_b[7]

		// Look for the OSG cvmfs public key to verify signature
		prefix := os.Getenv("OSG_LOCATION", "/")
		osgpub := "opensciencegrid.org.pub"
		pubkey_files := []string{"/etc/cvmfs/keys/opensciencegrid.org/" + osgpub, path.Join(prefix, "etc/stashcache", osgpub),
			path.Join(prefix, "usr/share/stashcache", osgpub)}

		if resource_filename != nil {

			for _, pubkey_file := range pubkey_files {

				if _, err := os.Stat(pubkey_file); err == nil {
					break
				} else {
					log.Error("Unable to find osg cvmfs key in %r", pubkey_files)
					return nil
				}
			}

			cmd := "/usr/bin/openssl rsautl -verify -pubin -inkey " + pubkey_file
			log.Debug("Running %s", cmd)

			command_object := exec.Command(cmd)
			stdin, err := command_object.StdinPipe()
			io.WriteString(stdin, hashStr)
			decryptedhash, err := cmd.CombinedOutput()

			if hash_str != decryptedhash {
				log.Debug("stashservers hash %s does not match decrypted signature %s", hash_str, decryptedhash)
				log.Error("stashservers signature does not verify")
				return nil
			}

			log.Debug("Signature Matched")

			log.Debug("Cache list: %s", responselines_b[4]).split(';')

			if print_cache_list_names {
				names := ""
				//Skip hash at the end

				//?????
				for _, l := range myList {
					names = names + "," + strings.Split(l, "=")

					//Skip leading commas
					fmt.Printf(names)
				}

				if caches_list_name != nil {
					caches = strings.Split(lists, "=")
				} else {
					for _, l := range lists {
						n := len(caches_list_name) + 1

						if l == cache_list_name+"=" {
							caches = l
						}
					}
				}

				caches_list = strings.Split(caches, ",")
				for _, i := range len(caches_list) {
					caches_list[i] = "root://" + caches_list[i]
				}

				return caches_list

			} else {
				log.Debug("Unable to retrieve caches.json using resource string, trying other locations")
			}

		}
	}
}
