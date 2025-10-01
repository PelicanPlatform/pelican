/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

//
// This file generates the authorization configuration for the XRootD
// server.  Particularly, it generates the scitokens.cfg the server will
// use to interpret the tokens.
//

package xrootd

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"github.com/go-ini/ini"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/pelicanplatform/pelican/cache"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

type (

	// XRootD server-wide configurations for SciTokens.
	GlobalCfg struct {
		Audience []string
	}

	// Per-issuer configuration
	Issuer struct {
		Name            string
		Issuer          string
		BasePaths       []string
		RestrictedPaths []string
		MapSubject      bool
		DefaultUser     string
		UsernameClaim   string
		NameMapfile     string
		RequiredAuth    string
		AcceptableAuth  string
	}

	// Top-level configuration object for the template
	ScitokensCfg struct {
		Global    GlobalCfg
		IssuerMap map[string]Issuer
	}
)

var (
	//go:embed resources/scitokens.cfg
	scitokensCfgTemplate string
)

// Remove a trailing carriage return from a slice. Used by scanLinesWithCont
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

// Scan through the lines of a file, respecting line continuation characters. That is,
//
// ```
// foo \
// bar
// ```
//
// Would be parsed as a single line, `foo bar`.
//
// Follows the ScanFunc interface defined by bufio.
func ScanLinesWithCont(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	curData := data
	for {
		firstControl := bytes.IndexAny(curData, "\\\n")
		if firstControl < 0 {
			if atEOF {
				// EOF and no more control characters; gobble up the rest
				token = append(token, curData...)
				advance += len(curData)
				return
			} else {
				// Not the end of the stream -- ask for more data to see if we get a full line.
				return 0, nil, nil
			}
		} else if curData[firstControl] == '\\' {
			// There's a line continuation.  Ignore the rest of the whitespace, advance to new line.
			token = append(token, curData[0:firstControl]...)
			idx := firstControl + 1
			for {
				if idx == len(curData) {
					break
				} else if curData[idx] == '\n' {
					idx += 1
					break
				} else if unicode.IsSpace(rune(curData[idx])) {
					idx += 1
				} else {
					return 0, nil, errors.Errorf("invalid character after line continuation: %s", string(curData[idx]))
				}
			}
			curData = curData[idx:]
			advance += idx
		} else { // must be a newline.  Return.
			token = dropCR(append(token, curData[0:firstControl]...))
			advance += firstControl + 1
			return
		}
	}
}

func deduplicateBasePaths(cfg *ScitokensCfg) {
	for key, item := range cfg.IssuerMap {
		bps := item.BasePaths
		slices.Sort(bps)
		bps = slices.Compact(bps)
		item.BasePaths = bps
		cfg.IssuerMap[key] = item
	}
}

// Given a reference to a Scitokens configuration, write it out to a known location
// on disk for the xrootd server
//
// isFirstRun is true if this is the first time we write the scitokens.cfg file, false otherwise.
// If the drop privileges feature is enabled, the first run is by the root user,
// and the subsequent runs are by the unprivileged pelican user via the xrdhttp-pelican plugin.
func writeScitokensConfiguration(modules server_structs.ServerType, cfg *ScitokensCfg, isFirstRun bool) error {

	JSONify := func(v any) (string, error) {
		result, err := json.Marshal(v)
		return string(result), err
	}
	templ := template.Must(template.New("scitokens.cfg").
		Funcs(template.FuncMap{"StringsJoin": strings.Join, "JSONify": JSONify}).
		Parse(scitokensCfgTemplate))

	// After startup (the first run), if Pelican is run by unprivileged user, we use
	// xrdhttp-pelican plugin to make sure the final scitokens.cfg file is owned by xrootd
	if !isFirstRun && param.Server_DropPrivileges.GetBool() {
		// Create a temporary file to assemble the scitokens configuration
		tempCfgFile, err := os.CreateTemp("", "scitokens-generated-*.cfg.tmp")
		if err != nil {
			return errors.Wrapf(err, "failed to create a temporary scitokens file %s", tempCfgFile.Name())
		} else {
			log.Debugln("Created temporary scitokens config file", tempCfgFile.Name())
		}
		defer func() {
			tempCfgFile.Close()
			os.Remove(tempCfgFile.Name())
		}()
		deduplicateBasePaths(cfg)
		err = templ.Execute(tempCfgFile, cfg)
		if err != nil {
			return errors.Wrapf(err, "unable to create scitokens.cfg template")
		}
		// After writing configuration to the file, the file pointer remains at the end.
		// Seek back to the beginning of the file so that the copy operation reads from the start.
		if _, err := tempCfgFile.Seek(0, io.SeekStart); err != nil {
			return errors.Wrap(err, "failed to seek to beginning of the file")
		}

		// Use command "7" in xrdhttp-pelican plugin to transplant the scitoken config file to a
		// directory owned by xrootd. The directory is specified in `xrootd/launch.go`. This is because
		// the xrootd daemon will periodically reload the scitokens.cfg and, in some cases, we may
		// want to update it without restarting the server.
		if err = FileCopyToXrootdDir(modules.IsEnabled(server_structs.OriginType), 7, tempCfgFile); err != nil {
			return errors.Wrap(err, "failed to copy the scitokens config file to the xrootd directory")
		}

		return nil
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	xrootdRun := param.Origin_RunLocation.GetString()
	if modules.IsEnabled(server_structs.CacheType) {
		xrootdRun = param.Cache_RunLocation.GetString()
	}

	configPath := filepath.Join(xrootdRun, "scitokens-generated.cfg.tmp")
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return errors.Wrapf(err, "failed to create a temporary scitokens file %s", configPath)
	}
	defer file.Close()
	if err = os.Chown(configPath, -1, gid); err != nil {
		return errors.Wrapf(err, "unable to change ownership of generated scitokens"+
			" configuration file %v to desired daemon gid %v", configPath, gid)
	}

	deduplicateBasePaths(cfg)
	err = templ.Execute(file, cfg)
	if err != nil {
		return errors.Wrapf(err, "unable to create scitokens.cfg template")
	}

	// Note that we write to the file then rename it into place.  This is because the
	// xrootd daemon will periodically reload the scitokens.cfg and, in some cases,
	// we may want to update it without restarting the server.
	finalConfigPath := filepath.Join(xrootdRun, "scitokens-origin-generated.cfg")
	if modules.IsEnabled(server_structs.CacheType) {
		finalConfigPath = filepath.Join(xrootdRun, "scitokens-cache-generated.cfg")
	}
	if err = os.Rename(configPath, finalConfigPath); err != nil {
		return errors.Wrapf(err, "failed to rename scitokens.cfg to final location")
	}
	return nil
}

// Retrieves authorization auth files for OSDF caches and origins
// This function queries the topology url for the specific authfiles for the cache and origin
// and returns a pointer to a byte buffer containing the file contents, returns nil if the
// authfile doesn't exist - considering it an empty file
func getOSDFAuthFiles(server server_structs.XRootDServer) ([]byte, error) {
	var stype string
	if server.GetServerType().IsEnabled(server_structs.OriginType) {
		stype = "origin"
	} else {
		stype = "cache"
	}

	base, err := url.Parse(param.Federation_TopologyUrl.GetString())
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse("/" + stype + "/Authfile?fqdn=" + param.Server_Hostname.GetString())
	if err != nil {
		return nil, err
	}
	client := http.Client{Transport: config.GetTransport()}
	url := base.ResolveReference(endpoint)
	log.Debugf("Querying Topology for OSDF Authfile at '%s'", url.String())

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// If endpoint isn't in topology, we simply want to return an empty buffer
	// The cache an origin still run, but without any information from the authfile
	if resp.StatusCode == 404 {
		return nil, nil
	}
	buf := new(bytes.Buffer)

	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

/*
	Rules for parsing/merging authfiles (see https://xrootd.web.cern.ch/doc/dev56/sec_config.htm#_Toc119617465, section 4.1)

	The Authfile is used to control access to public namespaces in XRootD. Incoming requests are
	a tuple of (authorization, resource, operation), where some authorization (e.g. a SciToken) may
	or may not permit the operation on the resource.

	Every incoming request first consults the XRootD Scitokens plugin to see if the authorization
	permits the operation on the resource. If access via SciTokens does not succeed, the authfile
	is consulted second.

	Rules:
	- Each authfile entry must be uniquely identifiable by a combination of identity
	type and identifier. When merging an existing authfile with the service-generated
	one, take care to properly zip together entries with the same identityType:identity pair.
	- Within a single authfile entry, path prefixes must be sorted by length from longest
	to shortest. If XRootD matches an incoming request with an identifier, it will
	iterate along the prefixes from left to right and apply the policy of the first substring
	match it finds.
	- If constructing an authfile for an Origin, merge path entries but use the policy from
	the existing authfile if there is a conflict, e.g.
		# user-set authfile
		u * /foo lr
		# service-generated authfile
		u * /foo -a
		# merged authfile
		u * /foo lr
	This gives Origin admins the power to get in trouble if they want to by overriding
	the service-generated policy.
	- If constructing an authfile for a cache, log a warning on a conflict but apply
	the service generated policy. Caches MUST respect the policies discovered via the Federation.
	This makes it harder for cache admins to accidentally disobey the security policy of discovered
	Origins.
	- For any prefix the service may work with, its policy must be explicit in the authfile.
	That is, if the service must work with a public prefix /foo and a private prefix /bar,
	the authfile must explicitly provide public access for foo and remove public access for /bar
*/

// Stores the privileges associated with one path prefix in a given
// authfile line, e.g. "/foo lr" or "/bar -r"
type authPathComponent struct {
	prefix      string
	subtractive bool // if true, this component removes privileges
	reads       bool // authfile components only support listings (l) and reads (r)
	listings    bool
	// No need for other privileges XRootD supports because Pelican assumes
	// these are never granted via the authfile (and thus they don't need to
	// be explicitly taken away for protected cases).
}

// Converts the authPathComponent back into a string suitable for an authfile
func (apc authPathComponent) String() string {
	privileges := ""
	if apc.subtractive {
		privileges += "-"
	}
	if apc.listings {
		privileges += "l"
	}
	if apc.reads {
		privileges += "r"
	}

	return fmt.Sprintf("%s %s", apc.prefix, privileges)
}

// Stores one logical line of an authfile, e.g. "u * /foo lr /bar -r"
// When parsing an input authfile, the \ line break is ignored and all
// parts of the line are stored in the same authLine object.
type authLine struct {
	idType         string
	id             string
	authComponents map[string]*authPathComponent // key will be the path prefix
}

// Given a prefix and a set of privileges, construct the appropriate authfile entry.
// The authfile entry for each path should be explicit about whether an action is allowed, e.g.
// if a path does not allow public reads, we should construct /path -lr (minus removes a privilege)
// See section 4.1 of https://xrootd.web.cern.ch/doc/dev56/sec_config.htm#_Toc119617465
func constructAuthEntry(prefix string, caps server_structs.Capabilities) (authComp authPathComponent, err error) {
	// Check whether the incoming path and caps warrant an authfile entry
	if prefix == "" {
		err = errors.New("cannot construct authfile entry with empty prefix")
		return
	}

	authComp.prefix = path.Clean(prefix)

	// Determine whether the auth component should add privileges or remove them
	if !caps.PublicReads {
		authComp.subtractive = true
	}

	if caps.PublicReads || caps.Reads {
		authComp.reads = true
	}

	// For now, we always set listings to true -- Stats in Pelican require listings,
	// so even if an Origin admin does not enable them, the authfile still needs to
	// to encode that listings are allowed. The hope is that we can find a way to
	// work around this in the future so that we can truly enforce the namespace's
	// policies.
	// By putting this "always true" logic explicitly in `constructAuthEntry`, we
	// make sure this hard-coding only affects service-generated authfile entries
	// (which are always derived via the capabilities struct that come from Origin
	// exports), while incoming/merged authfiles can still remove this privilege.
	authComp.listings = true

	return
}

// Given a privilege set from an authfile policy, e.g. "lr" or "-r", parse it into its components.
// While the list of privileges XRootD supports is longer, Pelican authfiles only care about
// reads and listings because everything else is handled in the SciTokens plugin.
func authPolicyFromWord(word string) (reads bool, listings bool, subtractive bool, err error) {
	if word == "" {
		return false, false, false, errors.New("internal error: empty authfile policy word")
	}

	for idx, char := range word {
		switch char {
		case 'r':
			reads = true
		case 'l':
			listings = true
		case '-':
			if idx != 0 {
				return false, false, false, errors.Errorf("malformed authfile policy: '-', when included, must be the first character in a set of privileges")
			}
			subtractive = true
		default:
			return false, false, false, errors.Errorf("unrecognized authfile policy character: %c", char)
		}
	}

	return reads, listings, subtractive, nil
}

// Given an authfile line (where lines can be continued with a \), parse it
// and add its contents to the authLineMap. The authLineMap is keyed by the combination
// of ID type and ID, e.g. "u *" or "g somegroup", followed by space-delimited tuples of
// <path> <privileges>, e.g. "/foo lr /bar -lr"
func authPoliciesFromLine(line string, authLineMap map[string]*authLine) error {
	words := strings.Fields(line)

	if len(words) == 0 {
		return nil
	}

	// Skip over comments. While we could preserve them, the logic
	// to keep them next to the relevant authfile entry in the case of
	// merges is complicated -- they can be referenced via the input authfile.
	if words[0] == "#" {
		return nil
	}

	// Check the line to make sure it looks like every path is matched with a policy,
	// e.g. "/foo lr /bar -lr" is valid, but "/foo lr /bar" is not.
	// We check for 4 here because a valid line has an ID type, an ID, and at least
	// one path/policy pair.
	if len(words) < 4 || len(words)%2 != 0 {
		return errors.Errorf(
			"malformed authfile line in %s: %q\nEach entry must have an ID type, an ID, and then pairs of <path> <policy>, e.g. 'u * /foo lr /bar r'. This line has an unexpected number of fields",
			param.Xrootd_Authfile.GetString(), line,
		)
	}

	key := words[0] + " " + words[1] // e.g. "u *"

	// If this is the first time we've seen this authfile entry, create it
	if _, exists := authLineMap[key]; exists {
		// A duplicate entry here means the admin has two entries for the same ID type and ID,
		// which is bad config. Since we don't know what they really wanted to do, fail.
		return errors.Errorf("duplicate authfile entry for %s found in %s", key, param.Xrootd_Authfile.GetString())
	}

	authLineMap[key] = &authLine{
		idType:         words[0],
		id:             words[1],
		authComponents: map[string]*authPathComponent{},
	}

	authComponents := authLineMap[key].authComponents

	// Start walking through path/policy pairs
	for i := 2; i < len(words)-1; i += 2 {
		path := words[i]
		policy := words[i+1]

		if _, ok := authComponents[path]; ok {
			return errors.Errorf("duplicate path %s found for authfile entry %s in %s", path, key, param.Xrootd_Authfile.GetString())
		}

		reads, listings, subtractive, err := authPolicyFromWord(policy)
		if err != nil {
			return errors.Wrapf(err, "failed to parse authfile policy %q in line %s from %s", policy, line, param.Xrootd_Authfile.GetString())
		}
		authComponents[path] = &authPathComponent{
			prefix:      path,
			reads:       reads,
			listings:    listings,
			subtractive: subtractive,
		}
	}

	return nil
}

// Parse the contents of an authfile and add all entries to the authLinesMap.
// These will later be merged with any service-generated entries according to the service's merge policy.
func populateAuthLinesMapFromFile(contents []byte, authLineMap map[string]*authLine) error {
	sc := bufio.NewScanner(strings.NewReader(string(contents)))
	sc.Split(ScanLinesWithCont)
	log.Debugln("Parsing the input authfile")

	for sc.Scan() {
		// These lines have already joined any "continue" characters by the scan
		// split function, so they represent exactly one logical authfile line.
		lineContents := sc.Text()
		if err := authPoliciesFromLine(lineContents, authLineMap); err != nil {
			return errors.Wrap(err, "could not parse authfile line")
		}
	}

	return nil
}

// Populate the authLinesMap using any exports defined at the Origin.
// Public namespaces are added to grant privileges in the Authfile, while
// private namespaces are added to subtract privileges from public access.
func populateAuthLinesMapForOrigin(authLinesMap map[string]*authLine) error {
	// Next, add any public exports the origin has to the authfile map
	if !param.Origin_DisableDirectClients.GetBool() {
		log.Debugln("Adding Origin exports to authfile")
		originExports, err := server_utils.GetOriginExports()
		if err != nil {
			return errors.Wrapf(err, "failed to get Origin exports")
		}

		authl, exists := authLinesMap["u *"]
		if !exists {
			authLinesMap["u *"] = &authLine{
				idType:         "u",
				id:             "*",
				authComponents: map[string]*authPathComponent{},
			}

			// Origin entries are always placed under the "u *" entry so they apply to all users.
			authl = authLinesMap["u *"]
		}

		for _, export := range originExports {
			authComp, err := constructAuthEntry(export.FederationPrefix, export.Capabilities)
			if err != nil {
				return errors.Wrapf(err, "failed to construct authfile entry for Origin export %s", export.FederationPrefix)
			}

			// If the authfile already has an entry for this prefix, we prefer the admin-provided
			// definition and skip over the service-generated one (but log a warning). Origin admins
			// are allowed to dig themselves into a hole if they want to.
			if existingComp, ok := authl.authComponents[authComp.prefix]; ok {
				log.Warnf("Origin authfile already has an entry for prefix %s; using admin-provided policy %v instead of service-generated policy %v",
					authComp.prefix, *existingComp, authComp)
				continue
			}
			authl.authComponents[authComp.prefix] = &authComp
		}

		// Now add the `.well-known` path
		wkAuthComp, err := constructAuthEntry("/.well-known", server_structs.Capabilities{PublicReads: true, Reads: true, Listings: true})
		if err != nil {
			return errors.Wrapf(err, "failed to construct authfile entry for /.well-known")
		}
		if existingComp, ok := authl.authComponents[wkAuthComp.prefix]; ok {
			log.Warnf("Origin authfile already has an entry for prefix %s; using admin-provided policy %v instead of service-generated policy %v",
				wkAuthComp.prefix, *existingComp, wkAuthComp)
		} else {
			authl.authComponents[wkAuthComp.prefix] = &wkAuthComp
		}
	}

	return nil
}

// Populate the authLinesMap using any exports defined at the Cache.
// Public namespaces are added to grant privileges in the Authfile, while
// private namespaces are added to subtract privileges from public access.
// Unlike Origins, Caches must respect the policies discovered via the Federation
// so an admin-provided authfile entry is overridden by the service-generated
// entry on conflict. This is done to prevent a Cache admin from accidentally
// violating policies set by the Origin.
func populateAuthLinesMapForCache(authLinesMap map[string]*authLine, server server_structs.XRootDServer) error {
	authl, exists := authLinesMap["u *"]
	if !exists {
		authLinesMap["u *"] = &authLine{
			idType:         "u",
			id:             "*",
			authComponents: map[string]*authPathComponent{},
		}

		authl = authLinesMap["u *"]
	}

	log.Debugln("Adding Cache exports to authfile")
	for _, ad := range server.GetNamespaceAds() {
		authComp, err := constructAuthEntry(ad.Path, ad.Caps)
		if err != nil {
			return errors.Wrapf(err, "failed to construct authfile entry for Cache export %s", ad.Path)
		}

		// If the authfile already has an entry for this prefix, we prefer the discovered
		// definition and skip over the admin-provided one (but log a warning).
		if existingComp, ok := authl.authComponents[authComp.prefix]; ok {
			log.Warnf("Cache authfile already has an entry for prefix %s; using federation-discovered policy %v instead of service-generated policy %v",
				authComp.prefix, *existingComp, authComp)
		}
		authl.authComponents[authComp.prefix] = &authComp
	}

	// Now add the `.well-known` path
	wkAuthComp, err := constructAuthEntry("/.well-known", server_structs.Capabilities{PublicReads: true, Reads: true, Listings: true})
	if err != nil {
		return errors.Wrapf(err, "failed to construct authfile entry for /.well-known")
	}
	if existingComp, ok := authl.authComponents[wkAuthComp.prefix]; ok {
		// Here we still allow the admin to override the .well-known entry, but log a warning
		// because it's probably not what they want to do.
		log.Warnf("Cache authfile already has an entry for prefix %s; using admin-provided policy %v instead of service-generated policy %v",
			wkAuthComp.prefix, *existingComp, wkAuthComp)
	} else {
		authl.authComponents[wkAuthComp.prefix] = &wkAuthComp
	}

	return nil
}

// Given an authLine, serialize it into a string suitable for writing to an authfile.
// Sort the authComponents by descending prefix length so that XRootD applies the most
// specific policy first.
func serializeAuthLine(al authLine) string {
	// Collect and sort prefixes by descending length
	prefixes := make([]string, 0, len(al.authComponents))
	for prefix := range al.authComponents {
		prefixes = append(prefixes, prefix)
	}
	slices.SortFunc(prefixes, func(a, b string) int {
		if len(a) > len(b) {
			return -1 // a before b
		}
		if len(a) < len(b) {
			return 1 // b before a
		}
		return 0 // equal length
	})

	// Build the line
	parts := []string{al.idType, al.id}
	for _, prefix := range prefixes {
		parts = append(parts, al.authComponents[prefix].String())
	}
	return strings.Join(parts, " ")
}

// Given an authLinesMap, produce a slice of lines representing the sorted, serialized
// authfile according to:
// -- sort IDType:ID lines by ID length (longest first), but always put "u *" last
// -- within each authLine, sort the authComponents by descending prefix length
func getSortedSerializedAuthLines(authLinesMap map[string]*authLine) []string {
	var lines []string

	// Separate "u *" from other keys
	var otherKeys []string
	var uStarKey string
	for key := range authLinesMap {
		if key == "u *" {
			uStarKey = key
		} else {
			otherKeys = append(otherKeys, key)
		}
	}

	// Sort other keys by their authLine's id field (most specific first: longest id first, then lexicographically)
	slices.SortFunc(otherKeys, func(a, b string) int {
		idA := authLinesMap[a].id
		idB := authLinesMap[b].id
		// Sort by descending length (longest first)
		if len(idA) > len(idB) {
			return -1
		}
		if len(idA) < len(idB) {
			return 1
		}
		// If lengths are equal, sort lexicographically
		return strings.Compare(idA, idB)
	})

	// Add all non-u* lines first
	for _, key := range otherKeys {
		lines = append(lines, serializeAuthLine(*authLinesMap[key]))
	}
	// Add "u *" last, if present
	if uStarKey != "" {
		lines = append(lines, serializeAuthLine(*authLinesMap[uStarKey]))
	}

	return lines
}

// Given the set of authfile lines, write them to disk in the appropriate location
func writeAuthfile(server server_structs.XRootDServer, lines []string, isFirstRun bool) error {
	// Prepare the output buffer
	var output bytes.Buffer
	for _, line := range lines {
		output.WriteString(line)
		output.WriteByte('\n')
	}

	// If Pelican is run by unprivileged user, use xrdhttp-pelican plugin to ensure xrootd owns the file
	if !isFirstRun && param.Server_DropPrivileges.GetBool() {
		// Create a temporary authfile
		tempAuthFile, err := os.CreateTemp("", "temp-authfile-generated-*")
		if err != nil {
			return errors.Wrapf(err, "failed to create a generated temporary authfile")
		}
		log.Debugln("Created temporary authfile", tempAuthFile.Name())
		defer func() {
			tempAuthFile.Close()
			os.Remove(tempAuthFile.Name())
		}()
		if _, err := output.WriteTo(tempAuthFile); err != nil {
			return errors.Wrapf(err, "failed to write to generated authfile %v", tempAuthFile.Name())
		}
		// After writing content to the file, the file pointer remains at the end.
		// Seek back to the beginning of the file so that the copy operation reads from the start.
		if _, err := tempAuthFile.Seek(0, io.SeekStart); err != nil {
			return errors.Wrap(err, "failed to seek to beginning of the file")
		}

		// Transplant the authfile using the xrdhttp-pelican plugin so xrootd can access it.
		// Command "6" instructs the plugin to put the auth file into the designated location owned by "xrootd" user,
		// which is specified in `xrootd/launch.go`.
		if err = FileCopyToXrootdDir(server.GetServerType().IsEnabled(server_structs.OriginType), 6, tempAuthFile); err != nil {
			return errors.Wrap(err, "failed to copy the auth file to the xrootd directory")
		}
		return nil
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	xrootdRun := param.Origin_RunLocation.GetString()
	if server.GetServerType().IsEnabled(server_structs.CacheType) {
		xrootdRun = param.Cache_RunLocation.GetString()
	}

	finalAuthPath := filepath.Join(xrootdRun, "authfile-origin-generated")
	if server.GetServerType().IsEnabled(server_structs.CacheType) {
		finalAuthPath = filepath.Join(xrootdRun, "authfile-cache-generated")
	}
	file, err := os.OpenFile(finalAuthPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return errors.Wrapf(err, "failed to create a generated authfile %s", finalAuthPath)
	}
	defer file.Close()
	if err = os.Chown(finalAuthPath, -1, gid); err != nil {
		return errors.Wrapf(err, "unable to change ownership of generated authfile %v to desired daemon gid %v", finalAuthPath, gid)
	}
	if _, err := output.WriteTo(file); err != nil {
		return errors.Wrapf(err, "failed to write to generated authfile %v", finalAuthPath)
	}

	return nil
}

// Parse the input xrootd authfile, add any default configurations, and then save it
// into the xrootd runtime directory
//
// isFirstRun is true if this is the first time we are writing the authfile, false otherwise.
// If the drop privileges feature is enabled, the first run is by the root user,
// and the subsequent runs are by the unprivileged pelican user via the xrdhttp-pelican plugin.
func EmitAuthfile(server server_structs.XRootDServer, isFirstRun bool) error {
	// Used to hold the representations for every export needed for the authfile
	authLinesMap := map[string]*authLine{}

	// If we're using OSDF as our topology source, fetch the authfile from there
	// and parse it into the authLinesMap first.  This way, any user-provided
	// authfile entries will override the topology-provided ones.
	if config.GetPreferredPrefix() == config.OsdfPrefix &&
		((server.GetServerType().IsEnabled(server_structs.OriginType) && !param.Topology_DisableOriginX509.GetBool()) ||
			(server.GetServerType().IsEnabled(server_structs.CacheType) && !param.Topology_DisableCacheX509.GetBool())) {

		log.Debugln("Retrieving OSDF Authfile for server")
		contents, err := getOSDFAuthFiles(server)
		if err != nil {
			return errors.Wrapf(err, "Failed to fetch osdf authfile from topology")
		}

		log.Debugln("Parsing OSDF Topology Authfile")
		if contents != nil {
			if err := populateAuthLinesMapFromFile(contents, authLinesMap); err != nil {
				return errors.Wrapf(err, "failed to parse authfile fetched from OSDF Topology")
			}
		}
	}

	// Now parse the user-provided authfile into the map if it exists.
	userProvidedAuthfile := param.Xrootd_Authfile.GetString()
	if userProvidedAuthfile != "" {
		log.Debugf("Parsing authfile from %s", userProvidedAuthfile)
		contents, err := os.ReadFile(userProvidedAuthfile)
		if err != nil {
			return errors.Wrapf(err, "failed to read xrootd authfile from %s", userProvidedAuthfile)
		}
		if err := populateAuthLinesMapFromFile(contents, authLinesMap); err != nil {
			return errors.Wrapf(err, "failed to parse user-provided authfile")
		}
	}

	if server.GetServerType().IsEnabled(server_structs.OriginType) {
		// Add all exports from the Origin to the authfile, subtracting privileges for
		// protected namespaces while adding privileges for public namespaces
		if err := populateAuthLinesMapForOrigin(authLinesMap); err != nil {
			return errors.Wrapf(err, "failed to add origin exports to authfile")
		}
	}

	if server.GetServerType().IsEnabled(server_structs.CacheType) {
		// Do the same for Caches, but apply a different merge policy
		// on conflicts
		if err := populateAuthLinesMapForCache(authLinesMap, server); err != nil {
			return errors.Wrapf(err, "failed to add cache exports to authfile")
		}
	}

	sortedAuthfileLines := getSortedSerializedAuthLines(authLinesMap)

	return writeAuthfile(server, sortedAuthfileLines, isFirstRun)
}

// Given a filename, load and parse the file into a ScitokensCfg object
func LoadScitokensConfig(fileName string) (cfg ScitokensCfg, err error) {
	configIni, err := ini.Load(fileName)
	if err != nil {
		return cfg, errors.Wrapf(err, "unable to load the scitokens.cfg at %s", fileName)
	}

	cfg.IssuerMap = make(map[string]Issuer)

	if section, err := configIni.GetSection("Global"); err == nil {
		if audienceKey := section.Key("audience"); audienceKey != nil {
			for _, audience := range audienceKey.Strings(",") {
				cfg.Global.Audience = append(cfg.Global.Audience, strings.TrimSpace(audience))
			}
		}
		if audienceKey := section.Key("audience_json"); audienceKey != nil && audienceKey.String() != "" {
			var audiences []string
			if err := json.Unmarshal([]byte(audienceKey.String()), &audiences); err != nil {
				return cfg, errors.Wrapf(err, "unable to parse audience_json from %s", fileName)
			}
			for _, audience := range audiences {
				cfg.Global.Audience = append(cfg.Global.Audience, strings.TrimSpace(audience))
			}
		}
	}

	for _, sectionName := range configIni.Sections() {
		if !strings.HasPrefix(sectionName.Name(), "Issuer ") {
			continue
		}

		var newIssuer Issuer
		newIssuer.Name = sectionName.Name()[len("Issuer "):]
		if issuerKey := sectionName.Key("issuer"); issuerKey != nil {
			newIssuer.Issuer = issuerKey.String()
		}

		if basePathsKey := sectionName.Key("base_path"); basePathsKey != nil {
			for _, path := range basePathsKey.Strings(",") {
				newIssuer.BasePaths = append(newIssuer.BasePaths, strings.TrimSpace(path))
			}
		}

		if mapSubjectKey := sectionName.Key("map_subject"); mapSubjectKey != nil {
			newIssuer.MapSubject = mapSubjectKey.MustBool()
		}

		if defaultUserKey := sectionName.Key("default_user"); defaultUserKey != nil {
			newIssuer.DefaultUser = defaultUserKey.String()
		}

		if nameMapfileKey := sectionName.Key("name_mapfile"); nameMapfileKey != nil {
			newIssuer.NameMapfile = nameMapfileKey.String()
		}

		if usernameClaimKey := sectionName.Key("username_claim"); usernameClaimKey != nil {
			newIssuer.UsernameClaim = usernameClaimKey.String()
		}

		cfg.IssuerMap[newIssuer.Issuer] = newIssuer
	}

	return cfg, nil
}

// We have a special issuer just for self-monitoring the origin.
func GenerateMonitoringIssuer() (issuer Issuer, err error) {
	if enabled := param.Origin_SelfTest.GetBool(); !enabled {
		return
	}
	issuer.Name = "Built-in Monitoring"
	// We use server local issuer regardless of Server.IssuerUrl
	builtinIssuer := param.Server_ExternalWebUrl.GetString()
	if builtinIssuer == "" {
		err = errors.Errorf("unable to construct built-in monitoring issuer because no external web URL could be deduced. Is '%s' set?",
			param.Server_ExternalWebUrl.GetName())
		return
	}

	issuer.Issuer = builtinIssuer
	issuer.BasePaths = []string{server_utils.MonitoringBaseNs}
	issuer.DefaultUser = "xrootd"

	return
}

// Generate the federation issuer to ensure the client is federation authorized
func GenerateFederationIssuer() (issuer Issuer, err error) {
	if enabled := param.Origin_DisableDirectClients.GetBool(); !enabled {
		return
	}

	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return
	}

	if fedInfo.DiscoveryEndpoint == "" {
		err = errors.New("cannot create federation issuer, federation discovery endpoint not found")
		return
	}

	exports, err := server_utils.GetOriginExports()
	if err != nil {
		err = errors.Wrap(err, "failed to get origin exports in scitokens config")
		return
	}
	if len(exports) == 0 {
		err = errors.New("no exports found when configuring Origin scitokens config")
		return
	}

	// If the exports do not have public reads capabilities, then we want to set the
	// acceptable_authorization to be none for the federation issuer. Note that all
	// exports will have the same capabilities, so we can just check the first one.
	if !exports[0].Capabilities.PublicReads {
		issuer.AcceptableAuth = "none"
	}

	// Use a map to emulate a set
	pathSet := make(map[string]struct{})
	for _, export := range exports {
		pathSet[export.FederationPrefix] = struct{}{}
	}
	paths := maps.Keys(pathSet)

	issuer.Name = "Federation"
	issuer.Issuer = fedInfo.DiscoveryEndpoint
	issuer.BasePaths = paths
	issuer.RequiredAuth = "all"

	return
}

// Generate the scitokens issuer config for each export in the Origin.Exports block
//
// Exports map prefix --> issuers, but we need to remap that to issuer --> basePaths
// here.
// Because this function calls GetOriginExports(), anything that calls it must first
// have called `InitServer()` with the Origin module to initialize the relevant defaults
// for export generation.
func GenerateOriginIssuers() (issuers []Issuer, err error) {
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get origin exports in scitokens config")
	}
	if len(exports) == 0 {
		return nil, errors.New("no exports found when configuring Origin scitokens config")
	}

	// Reverse the mapping from prefix --> issuer to issuer --> basePaths
	// This isn't something we do for server advertisements, but the scitokens
	// config does treat these issuers as global entities, and we need to do this
	// to get the correct config.
	var issuerMap = make(map[string][]string)
	for _, export := range exports {
		for _, issUrl := range export.IssuerUrls {
			issuerMap[issUrl] = append(issuerMap[issUrl], export.FederationPrefix)
		}
	}

	issuers = make([]Issuer, 0)
	for issuer, basePaths := range issuerMap {
		issuers = append(issuers, Issuer{
			// "Origin" in the name indicates this issuer is responsible for data access at the
			// origin on behalf of a user-generated token.
			// Other issuers, e.g. "Director-based Monitoring" are for other Pelican services
			Name:            "Origin " + issuer,
			Issuer:          issuer,
			BasePaths:       basePaths,
			RestrictedPaths: param.Origin_ScitokensRestrictedPaths.GetStringSlice(),
			MapSubject:      param.Origin_ScitokensMapSubject.GetBool(),
			DefaultUser:     param.Origin_ScitokensDefaultUser.GetString(),
			UsernameClaim:   param.Origin_ScitokensUsernameClaim.GetString(),
			NameMapfile:     param.Origin_ScitokensNameMapFile.GetString(),
		})
	}

	return
}

// We have a special issuer just for director-based monitoring of the origin.
func GenerateDirectorMonitoringIssuer() (issuer Issuer, err error) {
	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return
	}
	if val := fedInfo.DirectorEndpoint; val == "" {
		return
	}
	issuer.Name = "Director-based Monitoring"
	issuer.Issuer = fedInfo.DirectorEndpoint
	issuer.BasePaths = []string{"/pelican/monitoring"}
	issuer.DefaultUser = "xrootd"

	return
}

// Makes the general scitokens config to be used by both the origin and the cache
func makeSciTokensCfg() (cfg ScitokensCfg, err error) {
	gid, err := config.GetDaemonGID()
	if err != nil {
		return cfg, err
	}

	// Create the scitokens.cfg file if it's not already present
	scitokensCfg := param.Xrootd_ScitokensConfig.GetString()

	err = config.MkdirAll(filepath.Dir(scitokensCfg), 0755, -1, gid)
	if err != nil {
		return cfg, errors.Wrapf(err, "unable to create directory %v",
			filepath.Dir(scitokensCfg))
	}
	// We only open the file without chmod to daemon group as we will make
	// a copy of this file and save it into xrootd run location
	if file, err := os.OpenFile(scitokensCfg, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640); err == nil {
		file.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return cfg, err
	}
	cfg, err = LoadScitokensConfig(scitokensCfg)
	if err != nil {
		return cfg, errors.Wrapf(err, "failed to load scitokens configuration at %s", scitokensCfg)
	}

	return cfg, nil
}

// Writes out the server's scitokens.cfg configuration
func EmitScitokensConfig(server server_structs.XRootDServer) error {
	if _, ok := server.(*origin.OriginServer); ok {
		return WriteOriginScitokensConfig(false)
	} else if cacheServer, ok := server.(*cache.CacheServer); ok {
		directorAds := cacheServer.GetNamespaceAds()
		if param.Cache_SelfTest.GetBool() {
			serverIssuerStr, err := config.GetServerIssuerURL()
			if err != nil {
				return errors.Wrapf(err, "could not determine server's issuer URL when generating scitokens config. Is '%s' set?", param.Server_IssuerUrl.GetName())
			}
			serverIssuer, err := url.Parse(serverIssuerStr)
			if err != nil {
				return errors.Wrap(err, "could not parse server's issuer URL when generating scitokens config")
			}
			cacheIssuer := server_structs.NamespaceAdV2{
				Caps: server_structs.Capabilities{PublicReads: false, Reads: true, Writes: true},
				Path: "/pelican/monitoring",
				Issuer: []server_structs.TokenIssuer{
					{
						BasePaths: []string{"/pelican/monitoring"},
						IssuerUrl: *serverIssuer,
					},
				},
			}
			directorAds = append(directorAds, cacheIssuer)
		}
		return WriteCacheScitokensConfig(directorAds, false)
	} else {
		return errors.New("internal error: server object is neither cache nor origin")
	}
}

// Writes out the origin's scitokens.cfg configuration
func WriteOriginScitokensConfig(isFirstRun bool) error {
	cfg, err := makeSciTokensCfg()
	if err != nil {
		return err
	}

	// Construct server audience, which all incoming tokens must match in their `aud` claim. Generally
	// this restricts tokens so that they're only respected by a single server.
	if aud := param.Origin_TokenAudience.GetString(); aud != "" && !slices.Contains(cfg.Global.Audience, aud) {
		cfg.Global.Audience = append(cfg.Global.Audience, aud)
	}
	log.Debugf("Origin is configured to use '%s' as token audience(s):", cfg.Global.Audience)

	// Generate all the origin's issuers. If none are configured per export and there are
	// no namespaces requiring an issuer, this list will be empty. If an issuer _is_ configured
	// for a namespace that doesn't require one, it's still added to the Scitokens config, but requests
	// with no token will fallback to the authfile for authorization.
	if issuers, err := GenerateOriginIssuers(); err == nil && len(issuers) > 0 {
		for _, issuer := range issuers {
			if val, ok := cfg.IssuerMap[issuer.Issuer]; ok {
				val.BasePaths = append(val.BasePaths, issuer.BasePaths...)
				val.Name += " and " + issuer.Name
				cfg.IssuerMap[issuer.Issuer] = val
			} else {
				cfg.IssuerMap[issuer.Issuer] = issuer
			}
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to generate xrootd issuers for the origin")
	}

	if issuer, err := GenerateMonitoringIssuer(); err == nil && len(issuer.Name) > 0 {
		if val, ok := cfg.IssuerMap[issuer.Issuer]; ok {
			val.BasePaths = append(val.BasePaths, issuer.BasePaths...)
			val.Name += " and " + issuer.Name
			cfg.IssuerMap[issuer.Issuer] = val
		} else {
			cfg.IssuerMap[issuer.Issuer] = issuer
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to generate xrootd issuer for self-monitoring")
	}

	if issuer, err := GenerateDirectorMonitoringIssuer(); err == nil && len(issuer.Name) > 0 {
		if val, ok := cfg.IssuerMap[issuer.Issuer]; ok {
			val.BasePaths = append(val.BasePaths, issuer.BasePaths...)
			val.Name += " and " + issuer.Name
			cfg.IssuerMap[issuer.Issuer] = val
		} else {
			cfg.IssuerMap[issuer.Issuer] = issuer
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to generate xrootd issuer for director-based monitoring")
	}

	if issuer, err := GenerateFederationIssuer(); err == nil && len(issuer.Name) > 0 {
		if val, ok := cfg.IssuerMap[issuer.Issuer]; ok {
			val.BasePaths = append(val.BasePaths, issuer.BasePaths...)
			val.Name += " and " + issuer.Name
			cfg.IssuerMap[issuer.Issuer] = val
		} else {
			cfg.IssuerMap[issuer.Issuer] = issuer
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to generate xrootd issuer for federation")
	}

	return writeScitokensConfiguration(server_structs.OriginType, &cfg, isFirstRun)
}

// GenerateCacheIssuers takes a slice of NamespaceAdV2 and generates a list of Issuer objects
// for the cache's scitokens configuration. It aggregates base paths for each issuer
// and removes duplicates, returning a slice of Issuer objects.
// This could be easily accomplished directly in WriteCacheScitokensConfig, but this split
// makes it slightly easier to test, as it doesn't require checking file contents for equality.
func GenerateCacheIssuers(nsAds []server_structs.NamespaceAdV2) []Issuer {
	// Map to aggregate base paths for each issuer
	var issuerMap = make(map[string][]string)
	for _, ad := range nsAds {
		if !ad.Caps.PublicReads {
			for _, issuer := range ad.Issuer {
				issuerMap[issuer.IssuerUrl.String()] = append(issuerMap[issuer.IssuerUrl.String()], issuer.BasePaths...)
			}
		}
	}

	// Deduplicate base paths for each issuer
	for issuer, basePaths := range issuerMap {
		slices.Sort(basePaths)                        // Sort the base paths
		issuerMap[issuer] = slices.Compact(basePaths) // Remove duplicates
	}

	issuers := make([]Issuer, 0, len(issuerMap))
	for issuer, basePaths := range issuerMap {
		issuers = append(issuers, Issuer{
			Name:      issuer,
			Issuer:    issuer,
			BasePaths: basePaths,
		})
	}

	return issuers
}

// Writes out the cache's scitokens.cfg configuration
func WriteCacheScitokensConfig(nsAds []server_structs.NamespaceAdV2, isFirstRun bool) error {
	cfg, err := makeSciTokensCfg()
	if err != nil {
		return err
	}

	issuers := GenerateCacheIssuers(nsAds)
	for _, issuer := range issuers {
		if val, ok := cfg.IssuerMap[issuer.Issuer]; ok {
			val.BasePaths = append(val.BasePaths, issuer.BasePaths...)
			cfg.IssuerMap[issuer.Issuer] = val
		} else {
			cfg.IssuerMap[issuer.Issuer] = issuer
		}
	}

	return writeScitokensConfiguration(server_structs.CacheType, &cfg, isFirstRun)
}

func EmitIssuerMetadata(exportPath string, xServeUrl string) error {
	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	keys, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return err
	}
	wellKnownPath := filepath.Join(exportPath, ".well-known")
	err = config.MkdirAll(wellKnownPath, 0755, -1, gid)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(wellKnownPath, "issuer.jwks"),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	buf, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal public keys")
	}
	_, err = file.Write(buf)
	if err != nil {
		return errors.Wrap(err, "failed to write public key set to export directory")
	}

	openidFile, err := os.OpenFile(filepath.Join(wellKnownPath, "openid-configuration"),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer openidFile.Close()

	jwksUrl, err := url.Parse(xServeUrl)
	if err != nil {
		return err
	}
	jwksUrl.Path = "/.well-known/issuer.jwks"

	cfg := server_structs.OpenIdDiscoveryResponse{
		Issuer:  xServeUrl,
		JwksUri: jwksUrl.String(),
	}

	// If we have the built-in issuer enabled, fill in the URLs for OA4MP
	if param.Origin_EnableIssuer.GetBool() {
		serviceUri := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/issuer"
		cfg.TokenEndpoint = serviceUri + "/token"
		cfg.UserInfoEndpoint = serviceUri + "/userinfo"
		cfg.RevocationEndpoint = serviceUri + "/revoke"
		cfg.GrantTypesSupported = []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "authorization_code"}
		cfg.ScopesSupported = []string{"openid", "offline_access", "wlcg", "storage.read:/",
			"storage.modify:/", "storage.create:/"}
		cfg.TokenAuthMethods = []string{"client_secret_basic", "client_secret_post"}
		cfg.RegistrationEndpoint = serviceUri + "/oidc-cm"
		cfg.DeviceEndpoint = serviceUri + "/device_authorization"
	}

	buf, err = json.MarshalIndent(cfg, "", " ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal OpenID configuration file contents")
	}
	_, err = openidFile.Write(buf)
	if err != nil {
		return errors.Wrap(err, "failed to write OpenID configuration file")
	}

	return nil
}
