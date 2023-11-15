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
package oa4mp

import (
	_ "embed"
	"os"
	"path/filepath"
	"text/template"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
)

type (
	oa4mpConfig struct {
		ClientID                string
		ClientSecret            string
		IssuerURL               string
		JwksLocation            string
		ScitokensServerLocation string
	}
)

var (
	//go:embed resources/server-config.xml
	serverConfigTmpl string

	//go:embed resources/proxy-config.xml
	proxyConfigTmpl string
)

func writeOA4MPConfig(oconf oa4mpConfig, fname, templateInput string) error {
	user, err := config.GetOA4MPUser()
	if err != nil {
		return err
	}

	templ := template.Must(template.New(fname).Parse(templateInput))

	etcPath := filepath.Join(param.Issuer_ScitokensServerLocation.GetString(), "etc")
	configPath := filepath.Join(etcPath, fname)
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = os.Chown(configPath, -1, user.Gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of configuration file %v"+
			" to desired daemon gid %v", configPath, user.Gid)
	}

	return templ.Execute(file, oconf)
}

func ConfigureOA4MP() (launcher daemon.Launcher, err error) {
	var oauth2Client oauth2.Config
	oauth2Client, err = oauth2.ServerOIDCClient()
	if err != nil {
		err = errors.Wrap(err, "Unable to launch token issuer component because OIDC is not configured")
		return
	}

	oconf := oa4mpConfig{
		ClientID:                oauth2Client.ClientID,
		ClientSecret:            oauth2Client.ClientSecret,
		IssuerURL:               param.Server_ExternalWebUrl.GetString() + "/api/v1.0/issuer",
		JwksLocation:            param.Server_IssuerJwks.GetString(),
		ScitokensServerLocation: param.Issuer_ScitokensServerLocation.GetString(),
	}

	err = writeOA4MPConfig(oconf, "server-config.xml", serverConfigTmpl)
	if err != nil {
		return
	}
	err = writeOA4MPConfig(oconf, "proxy-config.xml", proxyConfigTmpl)
	if err != nil {
		return
	}

	user, err := config.GetOA4MPUser()
	if err != nil {
		return
	}

	tomcatPath := filepath.Join(param.Issuer_TomcatLocation.GetString(), "bin", "catalina.sh")
	launcher = daemon.DaemonLauncher{
		DaemonName: "oa4mp",
		Args:       []string{tomcatPath, "run"},
		Uid:        user.Uid,
		Gid:        user.Gid,
	}

	return
}
