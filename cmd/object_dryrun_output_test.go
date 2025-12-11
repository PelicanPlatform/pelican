//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const dryRunSubprocessEnv = "DRYRUN_SUBPROCESS"

func TestDryRunOutputFormat(t *testing.T) {
	if os.Getenv(dryRunSubprocessEnv) == "1" {
		runDryRunSubprocess(t)
		return
	}

	server_utils.ResetTestState()

	originCfg := `
Origin:
  StorageType: "posix"
  EnableDirectReads: true
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["Reads", "Writes", "DirectReads", "Listings"]
`
	fed := fed_test_utils.NewFedTest(t, originCfg)

	host := fmt.Sprintf("%s:%d", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	discoveryURL := param.Federation_DiscoveryUrl.GetString()
	require.NotEmpty(t, discoveryURL)

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenCfg := token.NewWLCGToken()
	tokenCfg.Lifetime = time.Minute
	tokenCfg.Issuer = issuer
	tokenCfg.Subject = "test"
	tokenCfg.AddAudienceAny()
	tokenCfg.AddResourceScopes(
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/"),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/"),
	)
	tokStr, err := tokenCfg.CreateToken()
	require.NoError(t, err)
	tokenFile := filepath.Join(t.TempDir(), "token.jwt")
	require.NoError(t, os.WriteFile(tokenFile, []byte(tokStr), 0600))

	emptyCfg := filepath.Join(t.TempDir(), "empty.yaml")
	require.NoError(t, os.WriteFile(emptyCfg, []byte(""), 0644))

	exportPrefix := fed.Exports[0].FederationPrefix

	t.Run("object_get", func(t *testing.T) {
		destFile := filepath.Join(t.TempDir(), "downloaded.txt")
		srcURL := fmt.Sprintf("pelican://%s%s/hello_world.txt", host, exportPrefix)

		stdout, stderr, err := runDryRunCLI(t, discoveryURL, emptyCfg, []string{
			"object", "get",
			"--dry-run",
			"--token", tokenFile,
			srcURL,
			destFile,
		})
		require.NoError(t, err, "stderr: %s", stderr)

		lines := nonEmptyLines(stdout)
		require.Len(t, lines, 1)
		require.Equal(t, fmt.Sprintf("DOWNLOAD: %s -> %s", exportPrefix+"/hello_world.txt", destFile), lines[0])
		_, statErr := os.Stat(destFile)
		require.Error(t, statErr)
		require.True(t, os.IsNotExist(statErr))
	})

	t.Run("object_put", func(t *testing.T) {
		srcFile := filepath.Join(t.TempDir(), "upload_me.txt")
		require.NoError(t, os.WriteFile(srcFile, []byte("hello"), 0644))

		remotePath := exportPrefix + "/dryrun_upload.txt"
		dstURL := fmt.Sprintf("pelican://%s%s", host, remotePath)

		stdout, stderr, err := runDryRunCLI(t, discoveryURL, emptyCfg, []string{
			"object", "put",
			"--dry-run",
			"--token", tokenFile,
			srcFile,
			dstURL,
		})
		require.NoError(t, err, "stderr: %s", stderr)

		lines := nonEmptyLines(stdout)
		require.Len(t, lines, 1)
		require.Equal(t, fmt.Sprintf("UPLOAD: %s -> %s", srcFile, remotePath), lines[0])

		originFile := filepath.Join(fed.Exports[0].StoragePrefix, "dryrun_upload.txt")
		_, statErr := os.Stat(originFile)
		require.Error(t, statErr)
		require.True(t, os.IsNotExist(statErr))
	})

	t.Run("object_sync", func(t *testing.T) {
		localDir := filepath.Join(t.TempDir(), "src")
		require.NoError(t, os.MkdirAll(localDir, 0755))
		srcFile := filepath.Join(localDir, "sync_me.txt")
		require.NoError(t, os.WriteFile(srcFile, []byte("sync"), 0644))

		remoteDir := fmt.Sprintf("pelican://%s%s/syncdest/", host, exportPrefix)
		remotePath := exportPrefix + "/syncdest/sync_me.txt"

		stdout, stderr, err := runDryRunCLI(t, discoveryURL, emptyCfg, []string{
			"object", "sync",
			"--dry-run",
			"--token", tokenFile,
			localDir,
			remoteDir,
		})
		require.NoError(t, err, "stderr: %s", stderr)

		lines := nonEmptyLines(stdout)
		require.Len(t, lines, 1)
		require.Equal(t, fmt.Sprintf("UPLOAD: %s -> %s", srcFile, remotePath), lines[0])

		originFile := filepath.Join(fed.Exports[0].StoragePrefix, "syncdest", "sync_me.txt")
		_, statErr := os.Stat(originFile)
		require.Error(t, statErr)
		require.True(t, os.IsNotExist(statErr))
	})
}

func runDryRunSubprocess(t *testing.T) {
	argsJSON := os.Getenv("DRYRUN_ARGS_JSON")
	if argsJSON == "" {
		t.Fatalf("missing DRYRUN_ARGS_JSON")
	}
	var args []string
	require.NoError(t, json.Unmarshal([]byte(argsJSON), &args))

	rootCmd.SetArgs(args)
	defer rootCmd.SetArgs(nil)

	require.NoError(t, rootCmd.Execute())
}

func runDryRunCLI(t *testing.T, discoveryURL, cfgFile string, args []string) (stdout string, stderr string, err error) {
	argsFull := []string{"-test.run", "TestDryRunOutputFormat"}
	cmd := exec.Command(os.Args[0], argsFull...)

	argsJSON, jerr := json.Marshal(append([]string{"--config", cfgFile}, args...))
	require.NoError(t, jerr)

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("%s=1", dryRunSubprocessEnv),
		"DRYRUN_ARGS_JSON="+string(argsJSON),
		"PELICAN_FEDERATION_DISCOVERYURL="+discoveryURL,
		"PELICAN_TLSSKIPVERIFY=true",
		"PELICAN_LOGGING_DISABLEPROGRESSBARS=true",
	)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "PASS" {
			continue
		}
		// Skip coverage output lines that appear when running tests with -cover
		if strings.HasPrefix(line, "coverage:") {
			continue
		}
		out = append(out, line)
	}
	return out
}
