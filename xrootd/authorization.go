/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"github.com/go-ini/ini"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

// Remove a trailing carriage return from a slice.  Used by scanLinesWithCont
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

// Scan through the lines of a file, respecting line continuation characters.  That is,
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
func writeScitokensConfiguration(modules config.ServerType, cfg *ScitokensCfg) error {

	JSONify := func(v any) (string, error) {
		result, err := json.Marshal(v)
		return string(result), err
	}
	templ := template.Must(template.New("scitokens.cfg").
		Funcs(template.FuncMap{"StringsJoin": strings.Join, "JSONify": JSONify}).
		Parse(scitokensCfgTemplate))

	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	xrootdRun := param.Origin_RunLocation.GetString()
	if modules.IsEnabled(config.CacheType) {
		xrootdRun = param.Cache_RunLocation.GetString()
	}

	configPath := filepath.Join(xrootdRun, "scitokens-generated.cfg.tmp")
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return errors.Wrapf(err, "Failed to create a temporary scitokens file %s", configPath)
	}
	defer file.Close()
	if err = os.Chown(configPath, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of generated scitokens"+
			" configuration file %v to desired daemon gid %v", configPath, gid)
	}

	deduplicateBasePaths(cfg)
	err = templ.Execute(file, cfg)
	if err != nil {
		return errors.Wrapf(err, "Unable to create scitokens.cfg template")
	}

	// Note that we write to the file then rename it into place.  This is because the
	// xrootd daemon will periodically reload the scitokens.cfg and, in some cases,
	// we may want to update it without restarting the server.
	finalConfigPath := filepath.Join(xrootdRun, "scitokens-origin-generated.cfg")
	if modules.IsEnabled(config.CacheType) {
		finalConfigPath = filepath.Join(xrootdRun, "scitokens-cache-generated.cfg")
	}
	if err = os.Rename(configPath, finalConfigPath); err != nil {
		return errors.Wrapf(err, "Failed to rename scitokens.cfg to final location")
	}
	return nil
}

// Retrieves authorization auth files for OSDF caches and origins
// This function queries the topology url for the specific authfiles for the cache and origin
// and returns a pointer to a byte buffer containing the file contents, returns nil if the
// authfile doesn't exist - considering it an empty file
func getOSDFAuthFiles(server server_structs.XRootDServer) ([]byte, error) {
	var stype string
	if server.GetServerType().IsEnabled(config.OriginType) {
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
	log.Debugln("Querying OSDF url:", url.String())

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

// Parse the input xrootd authfile, add any default configurations, and then save it
// into the xrootd runtime directory
func EmitAuthfile(server server_structs.XRootDServer) error {
	authfile := param.Xrootd_Authfile.GetString()
	log.Debugln("Location of input authfile:", authfile)
	contents, err := os.ReadFile(authfile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read xrootd authfile from %s", authfile)
	}

	output := new(bytes.Buffer)
	foundPublicLine := false
	if config.GetPreferredPrefix() == config.OsdfPrefix {
		log.Debugln("Retrieving OSDF Authfile for server")
		bytes, err := getOSDFAuthFiles(server)
		if err != nil {
			return errors.Wrapf(err, "Failed to fetch osdf authfile from topology")
		}

		log.Debugln("Parsing OSDF Authfile")
		if bytes != nil {
			output.Write(bytes)
		}
	}

	sc := bufio.NewScanner(strings.NewReader(string(contents)))
	sc.Split(ScanLinesWithCont)
	log.Debugln("Parsing the input authfile")
	for sc.Scan() {
		lineContents := sc.Text()
		words := strings.Fields(lineContents)
		if len(words) >= 2 && words[0] == "u" && words[1] == "*" {
			// There exists a public access already in the authfile
			if server.GetServerType().IsEnabled(config.OriginType) {
				outStr := "u * /.well-known lr "
				// Set up public reads only for the namespaces that are public
				originExports, err := server_utils.GetOriginExports()
				if err != nil {
					return errors.Wrapf(err, "Failed to get origin exports")
				}

				for _, export := range originExports {
					if export.Capabilities.PublicReads {
						outStr += export.FederationPrefix + " lr "
					}
				}

				output.Write([]byte(outStr + strings.Join(words[2:], " ") + "\n"))
			} else {
				output.Write([]byte(lineContents + " "))
			}
			foundPublicLine = true
		} else {
			// Copy over entry verbatim
			output.Write([]byte(lineContents + "\n"))
		}
	}
	// If Origin has no authfile already exists, add the ./well-known to the authfile
	if !foundPublicLine && server.GetServerType().IsEnabled(config.OriginType) {
		outStr := "u * /.well-known lr"

		// Configure the Authfile for each of the public exports we have in the origin
		originExports, err := server_utils.GetOriginExports()
		if err != nil {
			return errors.Wrapf(err, "Failed to get origin exports")
		}

		for _, export := range originExports {
			if export.Capabilities.PublicReads {
				outStr += " " + export.FederationPrefix + " lr"
			}
		}

		outStr += "\n"
		output.Write([]byte(outStr))
	}

	// For the cache, add the public namespaces
	if server.GetServerType().IsEnabled(config.CacheType) {
		// If nothing has been written to the output yet
		var outStr string
		if !foundPublicLine {
			outStr = "u * "
		}
		for _, ad := range server.GetNamespaceAds() {
			if ad.Caps.PublicReads && ad.Path != "" {
				outStr += ad.Path + " lr "
			}
		}
		// A public namespace exists, so a line needs to be printed
		if len(outStr) > 4 {
			output.Write([]byte(outStr + "\n"))
		}
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	xrootdRun := param.Origin_RunLocation.GetString()

	if server.GetServerType().IsEnabled(config.CacheType) {
		xrootdRun = param.Cache_RunLocation.GetString()
	}

	finalAuthPath := filepath.Join(xrootdRun, "authfile-origin-generated")
	if server.GetServerType().IsEnabled(config.CacheType) {
		finalAuthPath = filepath.Join(xrootdRun, "authfile-cache-generated")
	}
	file, err := os.OpenFile(finalAuthPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return errors.Wrapf(err, "Failed to create a generated authfile %s", finalAuthPath)
	}
	defer file.Close()
	if err = os.Chown(finalAuthPath, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of generated auth"+
			"file %v to desired daemon gid %v", finalAuthPath, gid)
	}
	if _, err := output.WriteTo(file); err != nil {
		return errors.Wrapf(err, "Failed to write to generated authfile %v", finalAuthPath)
	}

	return nil
}

// Given a filename, load and parse the file into a ScitokensCfg object
func LoadScitokensConfig(fileName string) (cfg ScitokensCfg, err error) {
	configIni, err := ini.Load(fileName)
	if err != nil {
		return cfg, errors.Wrapf(err, "Unable to load the scitokens.cfg at %s", fileName)
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
				return cfg, errors.Wrapf(err, "Unable to parse audience_json from %s", fileName)
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
	if val := param.Origin_SelfTest.GetBool(); !val {
		return
	}
	issuer.Name = "Built-in Monitoring"
	// We use server local issuer regardless of Server.IssuerUrl
	issuer.Issuer = param.Server_ExternalWebUrl.GetString()
	issuer.BasePaths = []string{"/pelican/monitoring"}
	issuer.DefaultUser = "xrootd"

	return
}

func GenerateOriginIssuer(exportedPaths []string) (issuer Issuer, err error) {
	// TODO: Return to this and figure out how to get a proper unmarshal to work
	if len(exportedPaths) == 0 {
		return
	}
	issuer.Name = "Origin"
	issuerUrl, err := config.GetServerIssuerURL()
	if err != nil {
		return
	}
	issuer.Issuer = issuerUrl
	issuer.BasePaths = exportedPaths
	issuer.RestrictedPaths = param.Origin_ScitokensRestrictedPaths.GetStringSlice()
	issuer.MapSubject = param.Origin_ScitokensMapSubject.GetBool()
	issuer.DefaultUser = param.Origin_ScitokensDefaultUser.GetString()
	issuer.UsernameClaim = param.Origin_ScitokensUsernameClaim.GetString()

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
		return cfg, errors.Wrapf(err, "Unable to create directory %v",
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
		return cfg, errors.Wrapf(err, "Failed to load scitokens configuration at %s", scitokensCfg)
	}

	return cfg, nil
}

// Writes out the server's scitokens.cfg configuration
func EmitScitokensConfig(server server_structs.XRootDServer) error {
	if originServer, ok := server.(*origin.OriginServer); ok {
		authedPrefixes, err := originServer.GetAuthorizedPrefixes()
		if err != nil {
			return err
		}
		return WriteOriginScitokensConfig(authedPrefixes)
	} else if cacheServer, ok := server.(*cache.CacheServer); ok {
		directorAds := cacheServer.GetNamespaceAds()
		if param.Cache_SelfTest.GetBool() {
			localIssuer, err := url.Parse(param.Server_ExternalWebUrl.GetString())
			if err != nil {
				log.Error("Can't parse Server_ExternalWebUrl when generating scitokens config: ", err)
				return errors.Wrap(err, "can't parse Server_ExternalWebUrl when generating scitokens config")
			}
			cacheIssuer := server_structs.NamespaceAdV2{
				Caps: server_structs.Capabilities{PublicReads: false, Reads: true, Writes: true},
				Path: "/pelican/monitoring",
				Issuer: []server_structs.TokenIssuer{
					{
						BasePaths: []string{"/pelican/monitoring"},
						IssuerUrl: *localIssuer,
					},
				},
			}
			directorAds = append(directorAds, cacheIssuer)
		}
		return WriteCacheScitokensConfig(directorAds)
	} else {
		return errors.New("Internal error: server object is neither cache nor origin")
	}
}

// Writes out the origin's scitokens.cfg configuration
func WriteOriginScitokensConfig(authedPaths []string) error {
	cfg, err := makeSciTokensCfg()
	if err != nil {
		return err
	}
	if issuer, err := GenerateOriginIssuer(authedPaths); err == nil && len(issuer.Name) > 0 {
		if val, ok := cfg.IssuerMap[issuer.Issuer]; ok {
			val.BasePaths = append(val.BasePaths, issuer.BasePaths...)
			val.Name += " and " + issuer.Name
			cfg.IssuerMap[issuer.Issuer] = val
		} else {
			cfg.IssuerMap[issuer.Issuer] = issuer
			cfg.Global.Audience = append(cfg.Global.Audience, config.GetServerAudience())
		}
	} else if err != nil {
		return errors.Wrap(err, "failed to generate xrootd issuer for the origin")
	}

	if issuer, err := GenerateMonitoringIssuer(); err == nil && len(issuer.Name) > 0 {
		if val, ok := cfg.IssuerMap[issuer.Issuer]; ok {
			val.BasePaths = append(val.BasePaths, issuer.BasePaths...)
			val.Name += " and " + issuer.Name
			cfg.IssuerMap[issuer.Issuer] = val
		} else {
			cfg.IssuerMap[issuer.Issuer] = issuer
			cfg.Global.Audience = append(cfg.Global.Audience, config.GetServerAudience())
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

	return writeScitokensConfiguration(config.OriginType, &cfg)
}

// Writes out the cache's scitokens.cfg configuration
func WriteCacheScitokensConfig(nsAds []server_structs.NamespaceAdV2) error {
	cfg, err := makeSciTokensCfg()
	if err != nil {
		return err
	}
	for _, ad := range nsAds {
		if !ad.Caps.PublicReads {
			for _, ti := range ad.Issuer {
				if val, ok := cfg.IssuerMap[ti.IssuerUrl.String()]; ok {
					val.BasePaths = append(val.BasePaths, ti.BasePaths...)
					cfg.IssuerMap[ti.IssuerUrl.String()] = val
				} else {
					cfg.IssuerMap[ti.IssuerUrl.String()] = Issuer{Issuer: ti.IssuerUrl.String(), BasePaths: ti.BasePaths, Name: ti.IssuerUrl.String()}
				}
			}
		}
	}

	return writeScitokensConfiguration(config.CacheType, &cfg)
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
		return errors.Wrap(err, "Failed to marshal public keys")
	}
	_, err = file.Write(buf)
	if err != nil {
		return errors.Wrap(err, "Failed to write public key set to export directory")
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
		return errors.Wrap(err, "Failed to marshal OpenID configuration file contents")
	}
	_, err = openidFile.Write(buf)
	if err != nil {
		return errors.Wrap(err, "Failed to write OpenID configuration file")
	}

	return nil
}
