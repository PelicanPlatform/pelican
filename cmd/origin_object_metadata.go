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

// File origin_object_metadata.go implements `pelican origin object-metadata`,
// a thin CLI over the origin's local object-metadata tracking endpoints
// (see origin_serve/object_metadata_admin.go). Subcommands:
//
//   pelican origin object-metadata list     --namespace /foo
//   pelican origin object-metadata get      --namespace /foo --path /foo/bar.dat [--history N]
//   pelican origin object-metadata history  --namespace /foo --path /foo/bar.dat [--limit L]
//
// All subcommands authenticate via the same web-API admin token as
// `pelican downtime` (admin auth + login cookie).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/config"
)

var (
	originObjectMetadataCmd = &cobra.Command{
		Use:   "object-metadata",
		Short: "Inspect the origin's local object-metadata tracking database",
		Long: `Query the origin's local SQLite-backed object-metadata tracking layer.

This is a thin client over the origin's admin endpoints under
/api/v1.0/origin_ui/object_metadata. All subcommands require an
administrative token for the target origin (the same one
'pelican downtime' uses); pass it with --token or let the CLI
generate one from the origin's signing key when invoked locally.

Object-metadata tracking must be enabled on the origin
(Origin.Metadata.TrackAccess) for these endpoints to return data.`,
		Aliases: []string{"objectmd"},
	}

	originObjectMetadataListCmd = &cobra.Command{
		Use:   "list",
		Short: "List live (non-deleted) objects in a namespace",
		Args:  cobra.NoArgs,
		RunE:  runOriginObjectMetadataList,
	}

	originObjectMetadataGetCmd = &cobra.Command{
		Use:   "get",
		Short: "Get one object's live row (and optional history)",
		Args:  cobra.NoArgs,
		RunE:  runOriginObjectMetadataGet,
	}

	originObjectMetadataHistoryCmd = &cobra.Command{
		Use:   "history",
		Short: "List the full history for one object",
		Args:  cobra.NoArgs,
		RunE:  runOriginObjectMetadataHistory,
	}
)

func init() {
	// Object-metadata subtree under `pelican origin`. The
	// originCmd itself is defined in origin.go.
	originCmd.AddCommand(originObjectMetadataCmd)

	// Same persistent flags as `pelican downtime`. Reusing the
	// shared package-level vars (serverURLStr, tokenLocation)
	// declared in downtime.go.
	originObjectMetadataCmd.PersistentFlags().StringVarP(&serverURLStr, "server", "s", "",
		"Web URL of the Pelican origin (e.g. https://my-origin.com:8447)")
	originObjectMetadataCmd.PersistentFlags().StringVarP(&tokenLocation, "token", "t", "",
		"Path to the admin token file")

	originObjectMetadataCmd.AddCommand(originObjectMetadataListCmd)
	originObjectMetadataListCmd.Flags().String("namespace", "", "Federation prefix to list (required)")
	originObjectMetadataListCmd.Flags().Int("limit", 100, "Maximum rows per page (capped at 1000)")
	originObjectMetadataListCmd.Flags().Int("offset", 0, "Pagination offset")
	_ = originObjectMetadataListCmd.MarkFlagRequired("namespace")

	originObjectMetadataCmd.AddCommand(originObjectMetadataGetCmd)
	originObjectMetadataGetCmd.Flags().String("namespace", "", "Federation prefix of the object (required)")
	originObjectMetadataGetCmd.Flags().String("path", "", "Federation-rooted path of the object (required)")
	originObjectMetadataGetCmd.Flags().Int("history", 0, "If >0, also include the most recent N history rows")
	_ = originObjectMetadataGetCmd.MarkFlagRequired("namespace")
	_ = originObjectMetadataGetCmd.MarkFlagRequired("path")

	originObjectMetadataCmd.AddCommand(originObjectMetadataHistoryCmd)
	originObjectMetadataHistoryCmd.Flags().String("namespace", "", "Federation prefix of the object (required)")
	originObjectMetadataHistoryCmd.Flags().String("path", "", "Federation-rooted path of the object (required)")
	originObjectMetadataHistoryCmd.Flags().Int("limit", 100, "Maximum rows (capped at 1000)")
	_ = originObjectMetadataHistoryCmd.MarkFlagRequired("namespace")
	_ = originObjectMetadataHistoryCmd.MarkFlagRequired("path")
}

// originObjectMetadataAPIRequest issues a GET against the origin's
// admin endpoint and returns the body. Auth is the same web-admin
// token used by `pelican downtime`.
func originObjectMetadataAPIRequest(ctx context.Context, endpoint string, query url.Values) ([]byte, error) {
	apiURL, err := url.Parse(serverURLStr)
	if err != nil || apiURL.Scheme == "" {
		return nil, errors.Errorf("the --server flag must be a full URL, e.g. https://origin.example.com:8447 (got %q)", serverURLStr)
	}
	apiURL.Path = "/api/v1.0/origin_ui/object_metadata" + endpoint
	if len(query) > 0 {
		apiURL.RawQuery = query.Encode()
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(serverURLStr, tokenLocation)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain admin token")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create HTTP request")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())
	req.Header.Set("Accept", "application/json")

	log.Debugln("Requesting object-metadata from:", apiURL.String())
	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to execute request to %s", apiURL.String())
	}
	defer resp.Body.Close()
	body, err := handleAdminApiResponse(resp)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func runOriginObjectMetadataList(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}
	namespace, _ := cmd.Flags().GetString("namespace")
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	q := url.Values{}
	q.Set("namespace", namespace)
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", offset))
	}
	body, err := originObjectMetadataAPIRequest(ctx, "", q)
	if err != nil {
		return err
	}
	return printObjectMetadataJSONOrYAML(cmd, body)
}

func runOriginObjectMetadataGet(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}
	namespace, _ := cmd.Flags().GetString("namespace")
	path, _ := cmd.Flags().GetString("path")
	hist, _ := cmd.Flags().GetInt("history")

	q := url.Values{}
	q.Set("namespace", namespace)
	q.Set("path", path)
	if hist > 0 {
		q.Set("history", fmt.Sprintf("%d", hist))
	}
	body, err := originObjectMetadataAPIRequest(ctx, "/lookup", q)
	if err != nil {
		return err
	}
	return printObjectMetadataJSONOrYAML(cmd, body)
}

func runOriginObjectMetadataHistory(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}
	namespace, _ := cmd.Flags().GetString("namespace")
	path, _ := cmd.Flags().GetString("path")
	limit, _ := cmd.Flags().GetInt("limit")

	q := url.Values{}
	q.Set("namespace", namespace)
	q.Set("path", path)
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	body, err := originObjectMetadataAPIRequest(ctx, "/history", q)
	if err != nil {
		return err
	}
	return printObjectMetadataJSONOrYAML(cmd, body)
}

// printObjectMetadataJSONOrYAML prints the API response either as
// JSON (when the root --json flag is set) or as YAML (default,
// matching the rest of the admin CLI surface).
func printObjectMetadataJSONOrYAML(cmd *cobra.Command, body []byte) error {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		// Server returned non-JSON; just dump the raw bytes.
		fmt.Println(string(body))
		return nil
	}
	useJSON := false
	if root := cmd.Root(); root != nil {
		useJSON, _ = root.PersistentFlags().GetBool("json")
	}
	if useJSON {
		out, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return errors.Wrap(err, "failed to marshal JSON")
		}
		fmt.Println(string(out))
		return nil
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return errors.Wrap(err, "failed to marshal YAML")
	}
	fmt.Print(string(out))
	return nil
}
