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
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/pelicanplatform/pelican/config"
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

	xrootdRun := viper.GetString("XrootdRun")
	configPath := filepath.Join(xrootdRun, "scitokens-generated.cfg.tmp")
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	if err = os.Chown(configPath, -1, gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of generated scitokens"+
			" configuration file %v to desired daemon gid %v", configPath, gid)
	}
	defer file.Close()

	err = templ.Execute(file, cfg)
	if err != nil {
		return err
	}

	// Note that we write to the file then rename it into place.  This is because the
	// xrootd daemon will periodically reload the scitokens.cfg and, in some cases,
	// we may want to update it without restarting the server.
	finalConfigPath := filepath.Join(xrootdRun, "scitokens-generated.cfg")
	if err = os.Rename(configPath, finalConfigPath); err != nil {
		return err
	}
	return nil
}

// Given a filename, load and parse the file into a ScitokensCfg object
func LoadConfig(fileName string) (ScitokensCfg, error) {
	cfg := ScitokensCfg{}

	return cfg, errors.New("Config loader not implemented!")
}

// We have a special issuer just for self-monitoring the origin.
func GenerateMonitoringIssuer() (ScitokensCfg, error) {
	return ScitokensCfg{}, errors.New("GenerateMonitoringIssuer is not implemented")
}

// Writes out the origin's scitokens.cfg configuration
func WriteOriginScitokensConfig() error {
	return errors.New("WriteOriginScitokensConfig is not implemented")
}
