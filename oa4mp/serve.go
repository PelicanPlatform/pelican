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
	"strings"
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
		ScopesRequested         map[string]bool
		OIDCIssuerURL           string
		OIDCAuthorizationURL    string
		OIDCTokenEndpointURL    string
		OIDCDeviceAuthURL       string
		OIDCUserInfoURL         string
		OIDCAuthnReqs           []oidcAuthenticationRequirements
		OIDCAuthnUserClaim      string
		GroupSource             string
		GroupFile               string
		GroupRequirements       []string
		GroupAuthzTemplates     []authzTemplate
		UserAuthzTemplates      []authzTemplate
	}

	oidcAuthenticationRequirements struct {
		Claim string `mapstructure:"claim"`
		Value string `mapstructure:"value"`
	}

	authzTemplate struct {
		Actions []string `mapstructure:"actions"`
		Prefix  string   `mapstructure:"prefix"`
	}
)

var (
	//go:embed resources/server-config.xml
	serverConfigTmpl string

	//go:embed resources/proxy-config.xml
	proxyConfigTmpl string

	//go:embed resources/policies.qdl
	policiesQdlTmpl string

	//go:embed resources/id_token_policies.qdl
	idTokenPoliciesQdlTmpl string
)

func writeOA4MPConfig(oconf oa4mpConfig, fname, templateInput string) error {
	user, err := config.GetOA4MPUser()
	if err != nil {
		return err
	}

	templ := template.Must(template.New(fname).Parse(templateInput))

	file, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = os.Chown(fname, -1, user.Gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of configuration file %v"+
			" to desired daemon gid %v", fname, user.Gid)
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

	// For now, we only request the openid scope -- but OA4MP requires us to list all the ones we
	// don't want as well.
	scopesSupported, err := config.GetOIDCSupportedScopes()
	if err != nil {
		err = errors.Wrap(err, "Unable to launch token issuer due to OIDC configuration issue")
		return
	}
	scopesRequested := make(map[string]bool, len(scopesSupported))
	for _, scope := range scopesSupported {
		switch scope {
		case "openid":
			scopesRequested[scope] = true
		default:
			scopesRequested[scope] = false
		}
	}

	oidcIssuerURL := param.OIDC_Issuer.GetString()
	if oidcIssuerURL == "" {
		err = errors.New("OIDC.Issuer not set in the configuration")
		return
	}
	oidcAuthzURL, err := config.GetOIDCAuthorizationEndpoint()
	if err != nil {
		err = errors.Wrap(err, "OIDC authorization endpoint not available")
		return
	}
	oidcTokenURL, err := config.GetOIDCTokenEndpoint()
	if err != nil {
		err = errors.Wrap(err, "OIDC token endpoint not available")
		return
	}
	oidcDeviceAuthURL, err := config.GetOIDCDeviceAuthEndpoint()
	if err != nil {
		err = errors.Wrap(err, "OIDC device auth endpoint not available")
		return
	}
	oidcUserInfoURL, err := config.GetOIDCUserInfoEndpoint()
	if err != nil {
		err = errors.Wrap(err, "OIDC user info endpoint not available")
		return
	}

	oidcAuthnReqs := []oidcAuthenticationRequirements{}
	if err = param.Issuer_OIDCAuthenticationRequirements.Unmarshal(&oidcAuthnReqs); err != nil {
		err = errors.Wrap(err, "Failed to parse the Issuer.OIDCAuthenticationRequirements config")
		return
	}

	oidcAuthnUserClaim := param.Issuer_OIDCAuthenticationUserClaim.GetString()
	groupSource := param.Issuer_GroupSource.GetString()
	groupFile := param.Issuer_GroupFile.GetString()
	if groupFile == "" && groupSource == "file" {
		err = errors.New("Issuer.GroupFile must be set to use the 'file' group source")
		return
	}
	groupReqs := param.Issuer_GroupRequirements.GetStringSlice()

	authzTemplates := []authzTemplate{}
	if err = param.Issuer_AuthorizationTemplates.Unmarshal(&authzTemplates); err != nil {
		err = errors.Wrap(err, "Failed to parse the Issuer.AuthorizationTemplates config")
		return
	}
	groupAuthzTemplates := []authzTemplate{}
	userAuthzTemplates := []authzTemplate{}
	for _, authz := range authzTemplates {
		scope_actions := []string{}
		for _, scope := range authz.Actions {
			switch scope {
			case "read":
				scope_actions = append(scope_actions, "storage.read")
			case "write":
				scope_actions = append(scope_actions, "storage.modify")
			case "create":
				scope_actions = append(scope_actions, "storage.create")
			case "modify":
				scope_actions = append(scope_actions, "storage.modify")
			default:
				scope_actions = append(scope_actions, scope)
			}
		}
		authz.Actions = scope_actions
		if strings.Contains(authz.Prefix, "$GROUP") {
			groupAuthzTemplates = append(groupAuthzTemplates, authz)
		} else {
			// If it's not a group template, we assume there's an entry per user
			// (regardless of whether or not $USER is in the prefix template).
			userAuthzTemplates = append(userAuthzTemplates, authz)
		}
	}

	oconf := oa4mpConfig{
		ClientID:                oauth2Client.ClientID,
		ClientSecret:            oauth2Client.ClientSecret,
		IssuerURL:               "https://" + config.ComputeExternalAddress() + "/api/v1.0/issuer",
		JwksLocation:            param.Server_IssuerJwks.GetString(),
		ScitokensServerLocation: param.Issuer_ScitokensServerLocation.GetString(),
		ScopesRequested:         scopesRequested,
		OIDCIssuerURL:           oidcIssuerURL,
		OIDCAuthorizationURL:    oidcAuthzURL,
		OIDCTokenEndpointURL:    oidcTokenURL,
		OIDCDeviceAuthURL:       oidcDeviceAuthURL,
		OIDCUserInfoURL:         oidcUserInfoURL,
		OIDCAuthnReqs:           oidcAuthnReqs,
		OIDCAuthnUserClaim:      oidcAuthnUserClaim,
		GroupSource:             groupSource,
		GroupFile:               groupFile,
		GroupRequirements:       groupReqs,
		GroupAuthzTemplates:     groupAuthzTemplates,
		UserAuthzTemplates:      userAuthzTemplates,
	}

	etcPath := filepath.Join(param.Issuer_ScitokensServerLocation.GetString(), "etc")
	varQdlScitokensPath := filepath.Join(param.Issuer_ScitokensServerLocation.GetString(), "var",
		"qdl", "scitokens")

	err = writeOA4MPConfig(oconf, filepath.Join(etcPath, "server-config.xml"), serverConfigTmpl)
	if err != nil {
		return
	}
	err = writeOA4MPConfig(oconf, filepath.Join(etcPath, "proxy-config.xml"), proxyConfigTmpl)
	if err != nil {
		return
	}
	if err = writeOA4MPConfig(oconf, filepath.Join(varQdlScitokensPath, "policies.qdl"), policiesQdlTmpl); err != nil {
		return
	}
	if err = writeOA4MPConfig(oconf, filepath.Join(varQdlScitokensPath, "id_token_policies.qdl"), idTokenPoliciesQdlTmpl); err != nil {
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
