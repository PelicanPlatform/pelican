/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	_ "embed"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-ini/ini"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type (

	// XRootD server-wide configurations for SciTokens.
	GlobalCfg struct {
		Audience []string
	}

	// Per-issuer configuration
	Issuer struct {
		Name          string
		Issuer        string
		BasePaths     []string
		MapSubject    bool
		DefaultUser   string
		UsernameClaim string
		NameMapfile   string
	}

	// Top-level configuration object for the template
	ScitokensCfg struct {
		Global  GlobalCfg
		Issuers []Issuer
	}

	openIdConfig struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
)

var (
	//go:embed resources/scitokens.cfg
	scitokensCfgTemplate string
)

// Given a reference to a Scitokens configuration, write it out to a known location
// on disk for the xrootd server
func EmitScitokensConfiguration(cfg *ScitokensCfg) error {

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

	xrootdRun := param.XrootdRun.GetString()
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

	err = templ.Execute(file, cfg)
	if err != nil {
		return errors.Wrapf(err, "Unable to create scitokens.cfg template")
	}

	// Note that we write to the file then rename it into place.  This is because the
	// xrootd daemon will periodically reload the scitokens.cfg and, in some cases,
	// we may want to update it without restarting the server.
	finalConfigPath := filepath.Join(xrootdRun, "scitokens-generated.cfg")
	if err = os.Rename(configPath, finalConfigPath); err != nil {
		return errors.Wrapf(err, "Failed to rename scitokens.cfg to final location")
	}
	return nil
}

// Parse the input xrootd authfile, add any default configurations, and then save it
// into the xrootd runtime directory
func EmitAuthfile() error {
	authfile := viper.GetString("Authfile")
	contents, err := os.ReadFile(authfile)
	if err != nil {
		return errors.Wrapf(err, "Failed to read xrootd authfile from %s", authfile)
	}

	sc := bufio.NewScanner(strings.NewReader(string(contents)))
	output := new(bytes.Buffer)
	foundPublicLine := false
	for sc.Scan() {
		lineContents := sc.Text()
		words := strings.Fields(lineContents)
		if len(words) >= 2 && words[0] == "u" && words[1] == "*" {
			output.Write([]byte("u * /.well-known lr " + strings.Join(words[2:], " ") + "\n"))
			foundPublicLine = true
		} else {
			output.Write([]byte(lineContents + "\n"))
		}
	}
	if !foundPublicLine {
		output.Write([]byte("u * /.well-known lr\n"))
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	xrootdRun := viper.GetString("XrootdRun")
	finalAuthPath := filepath.Join(xrootdRun, "authfile-generated")
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

	if section, err := configIni.GetSection("Global"); err == nil {
		audienceKey := section.Key("audience")
		if audienceKey != nil {
			for _, audience := range audienceKey.Strings(",") {
				cfg.Global.Audience = append(cfg.Global.Audience, strings.TrimSpace(audience))
			}
		}
		audienceKey = section.Key("audience_json")
		if audienceKey != nil {
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

		cfg.Issuers = append(cfg.Issuers, newIssuer)
	}

	return cfg, nil
}

// We have a special issuer just for self-monitoring the origin.
func GenerateMonitoringIssuer() (issuer Issuer, err error) {
	if val := viper.GetBool("Origin.SelfTest"); !val {
		return
	}
	issuer.Name = "Built-in Monitoring"
	issuer.Issuer = viper.GetString("OriginUrl")
	issuer.BasePaths = []string{"/pelican/monitoring"}
	issuer.DefaultUser = "xrootd"

	return
}

// Writes out the origin's scitokens.cfg configuration
func WriteOriginScitokensConfig() error {

	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	// Create the scitokens.cfg file if it's not already present
	scitokensCfg := param.ScitokensConfig.GetString()
	err = config.MkdirAll(filepath.Dir(scitokensCfg), 0755, -1, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create directory %v",
			filepath.Dir(scitokensCfg))
	}
	if file, err := os.OpenFile(scitokensCfg, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640); err == nil {
		file.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if err = os.Chown(scitokensCfg, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of scitokens config %v"+
			" to desired daemon group %v", scitokensCfg, gid)
	}

	cfg, err := LoadScitokensConfig(scitokensCfg)
	if err != nil {
		return errors.Wrapf(err, "Failed to load scitokens configuration at %s", scitokensCfg)
	}

	if issuer, err := GenerateMonitoringIssuer(); err == nil && len(issuer.Name) > 0 {
		cfg.Issuers = append(cfg.Issuers, issuer)
		cfg.Global.Audience = append(cfg.Global.Audience, issuer.Issuer)
	}

	return EmitScitokensConfiguration(&cfg)
}

func EmitIssuerMetadata(exportPath string) error {
	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}

	keys, err := config.GenerateIssuerJWKS()
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

	originUrlStr := viper.GetString("OriginUrl")
	jwksUrl, err := url.Parse(originUrlStr)
	if err != nil {
		return err
	}
	jwksUrl.Path = "/.well-known/issuer.jwks"

	cfg := openIdConfig{
		Issuer:  viper.GetString("OriginUrl"),
		JWKSURI: jwksUrl.String(),
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
