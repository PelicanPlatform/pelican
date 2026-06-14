//go:build server

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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/config"
)

var (
	lotCmd = &cobra.Command{
		Use:   "lot",
		Short: "Manage storage lots (reservations) on a Pelican cache",
		Long: `Provide commands to list, inspect, create, update, delete, and reclaim storage
lots (reservations) on a Pelican cache. These commands interact with the
cache's lot management API and require an administrative token for the cache.`,
	}

	// lotServerURLStr is the cache web URL the lot subcommands target.
	lotServerURLStr string
	// lotTokenLocation is an optional path to an admin token file.
	lotTokenLocation string
)

func init() {
	rootCmd.AddCommand(lotCmd)

	// Required for all subcommands: the cache's web URL.
	lotCmd.PersistentFlags().StringVarP(&lotServerURLStr, "server", "s", "", "Web URL of the Pelican cache (e.g. https://my-cache.com:8447)")
	// Optional: an admin token file; if omitted, a short-lived admin token is generated.
	lotCmd.PersistentFlags().StringVarP(&lotTokenLocation, "token", "t", "", "Path to an admin token file")
}

// lotAPIDo issues an authenticated request to the cache lot API and returns the
// (success) response body. body may be nil for GET/DELETE. It mirrors the
// authentication used by the other admin CLI commands: an admin bearer token is
// supplied both as an Authorization header and a login cookie, satisfying the
// lot API's admin-cookie authorization path.
func lotAPIDo(ctx context.Context, method string, target *url.URL, body []byte) ([]byte, error) {
	tok, err := fetchOrGenerateWebAPIAdminToken(lotServerURLStr, lotTokenLocation)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewBuffer(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create HTTP request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, errors.New("Request cancelled")
		}
		return nil, errors.Wrapf(err, "Failed to execute request to %s", target.String())
	}
	defer resp.Body.Close()

	return handleAdminApiResponse(resp)
}

// cmdContext returns the command's context, defaulting to a background context.
func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// parseLotTimeFlag parses an optional UTC "YYYY-MM-DD HH:MM:SS" time flag into a
// pointer to Unix milliseconds. Returns (nil, nil) when the flag is unset.
func parseLotTimeFlag(cmd *cobra.Command, flagName string) (*int64, error) {
	s, _ := cmd.Flags().GetString(flagName)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid --%s value (use UTC 'YYYY-MM-DD HH:MM:SS')", flagName)
	}
	ms := t.UnixMilli()
	return &ms, nil
}

// printLotResult renders v as YAML (default) or JSON when the global --json flag
// is set, matching the output convention of the other admin commands.
func printLotResult(cmd *cobra.Command, v any) error {
	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return errors.Wrap(err, "Failed to marshal data to JSON")
		}
		fmt.Println(string(data))
		return nil
	}
	data, err := yaml.Marshal(v)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal data to YAML")
	}
	fmt.Print(string(data))
	return nil
}
