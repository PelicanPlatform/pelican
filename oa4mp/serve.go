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

package oa4mp

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"text/template"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
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
		Actions      []string `mapstructure:"actions"`
		Prefix       string   `mapstructure:"prefix"`
		Users        []string `mapstructure:"users"`
		Groups       []string `mapstructure:"groups"`
		GroupRegexes []string `mapstructure:"group_regexes"`
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

type compiledAuthz struct {
	Actions       []string
	Prefix        string
	UserSet       map[string]struct{}
	GroupLiterals map[string]struct{}
	GroupRegexes  []*regexp.Regexp
}

var compiledAuthzRules []*compiledAuthz

func compileAuthzRules(raw authzTemplate) (*compiledAuthz, error) {
	compiled := &compiledAuthz{
		Actions:       raw.Actions,
		Prefix:        raw.Prefix,
		UserSet:       make(map[string]struct{}),
		GroupLiterals: make(map[string]struct{}),
		GroupRegexes:  make([]*regexp.Regexp, 0, len(raw.GroupRegexes)),
	}

	for _, user := range raw.Users {
		compiled.UserSet[user] = struct{}{}
	}

	for _, group := range raw.Groups {
		compiled.GroupLiterals[group] = struct{}{}
	}

	for _, rgx := range raw.GroupRegexes {
		rx, err := regexp.Compile(rgx)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to compile group regex: %s", rgx)
		}
		compiled.GroupRegexes = append(compiled.GroupRegexes, rx)
	}

	return compiled, nil
}

func writeOA4MPFile(fname string, data []byte, perm os.FileMode) error {
	user, err := config.GetOA4MPUser()
	if err != nil {
		return err
	}

	file, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = os.Chown(fname, -1, user.Gid); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of configuration file %v"+
			" to desired daemon gid %v", fname, user.Gid)
	}

	if _, err = file.Write(data); err != nil {
		err = errors.Wrapf(err, "Failed to write OA4MP configuration file at %v", fname)
	}
	return err
}

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
	oauth2Client, _, err = oauth2.ServerOIDCClient()
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

	oidcIssuerURL := param.Issuer_IssuerClaimValue.GetString()
	if oidcIssuerURL == "" {
		oidcIssuerURL = param.Server_ExternalWebUrl.GetString()
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

	compiledAuthzRules = nil
	for _, authz := range authzTemplates {
		compiled, cErr := compileAuthzRules(authz)
		if cErr != nil {
			err = errors.Wrapf(cErr, "failed to compile authorization template: %v", authz)
			return
		}
		compiledAuthzRules = append(compiledAuthzRules, compiled)
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

	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		err = errors.Wrap(err, "Failed to load the private issuer key for running issuer")
		return
	}
	if err = key.Set("use", "sig"); err != nil {
		err = errors.Wrap(err, "Failed to configure private issuer key")
		return
	}
	jwks := jwk.NewSet()
	if err = jwks.AddKey(key); err != nil {
		return
	}

	buf, err := json.MarshalIndent(jwks, "", " ")
	if err != nil {
		err = errors.Wrap(err, "Failed to marshal issuer private key to JSON")
		return
	}
	etcPath := filepath.Join(param.Issuer_ScitokensServerLocation.GetString(), "etc")
	keyPath := filepath.Join(etcPath, "keys.jwk")
	if err = writeOA4MPFile(keyPath, buf, 0640); err != nil {
		return
	}

	oconf := oa4mpConfig{
		ClientID:                oauth2Client.ClientID,
		ClientSecret:            oauth2Client.ClientSecret,
		IssuerURL:               param.Server_ExternalWebUrl.GetString() + "/api/v1.0/issuer",
		JwksLocation:            keyPath,
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

	// If the HTTP socket already exists then tomcat will refuse to configure.
	socketName := filepath.Join(param.Issuer_ScitokensServerLocation.GetString(), "var", "http.sock")
	if err = os.Remove(socketName); err != nil && !errors.Is(err, syscall.ENOENT) {
		err = errors.Wrap(err, "failed to remove old tomcat communication socket")
		return
	}

	// Ensure the OA4MP storage directory exists and has correct permissions and ownership
	OA4MPStoragePath := "/opt/scitokens-server/var/storage"

	if err = os.Chmod(OA4MPStoragePath, 0700); err != nil {
		if os.IsNotExist(err) {
			log.Debugln("OA4MP storage directory does not exist. Creating", OA4MPStoragePath)
			if err = os.MkdirAll(OA4MPStoragePath, 0755); err != nil {
				err = errors.Wrap(err, "failed to create OA4MP storage directory")
				return
			}
			if err = os.Chmod(OA4MPStoragePath, 0700); err != nil {
				err = errors.Wrap(err, "failed to change the permissions of OA4MP storage directory after creating it")
				return
			}
		} else {
			err = errors.Wrap(err, "failed to change the permissions of OA4MP storage directory")
			return
		}
	}

	if err = os.Chown(OA4MPStoragePath, user.Uid, user.Gid); err != nil {
		err = errors.Wrap(err, "failed to change the ownership of OA4MP storage directory")
		return
	}

	qdlBoot := filepath.Join(param.Issuer_QDLLocation.GetString(), "var", "scripts", "boot.qdl")
	cmd := exec.Command(qdlBoot)
	cmd.Env = []string{
		"PATH=/bin:/usr/bin/:" + filepath.Join(param.Issuer_QDLLocation.GetString(), "bin"),
		"ST_HOME=" + param.Issuer_ScitokensServerLocation.GetString(),
		"QDL_HOME=" + param.Issuer_QDLLocation.GetString()}

	if err = customizeCmd(cmd); err != nil {
		return
	}

	stdoutErr, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorln("Failed to bootstrap the issuer environment")
		cmd_logger := log.WithFields(log.Fields{"daemon": "boot.qdl"})
		stdoutErrScanner := bufio.NewScanner(bytes.NewReader(stdoutErr))
		for stdoutErrScanner.Scan() {
			cmd_logger.Errorln("QDL Failure:", stdoutErrScanner.Text())
		}
		err = errors.Wrap(err, "Failed to bootstrap the issuer environment")
		return
		//err = nil
	}
	log.Debugln("Output from issuer environment bootstrap script:", string(stdoutErr))

	tomcatPath := filepath.Join(param.Issuer_TomcatLocation.GetString(), "bin", "catalina.sh")
	launcher = daemon.DaemonLauncher{
		DaemonName: "oa4mp",
		Args:       []string{tomcatPath, "run"},
		Uid:        user.Uid,
		Gid:        user.Gid,
	}

	return
}
