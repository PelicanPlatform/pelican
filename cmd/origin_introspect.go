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

// Introspecting a running origin's storage backend.
//
// The offline `pstore` commands need the origin stopped, because the store
// holds an exclusive lock on its directory.  These ask the running origin
// instead, over its administrative storage API.
//
// Only questions that are meaningful against a moving target are available.
// Listing, stat, usage, and digests describe a moment.  A consistency check
// does not -- scanning an index while it is being rewritten produces findings
// that cannot be distinguished from real ones -- so fsck stays with the
// offline commands, where its answers mean something.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	originIntrospectServer string
	originIntrospectToken  string
	originIntrospectJSON   bool
	originIntrospectLimit  int

	originIntrospectCmd = &cobra.Command{
		Use:   "introspect",
		Short: "Inspect a running origin's storage backend",
		Long: `Inspect the storage backend of an origin that is currently running.

These commands ask the origin over its administrative API, so they work while
it is serving. They are the live counterpart to "pelican-server origin pstore", which
reads the store directly and therefore requires the origin to be stopped.

CURRENTLY PSTORE ONLY. The endpoints these use exist only when the origin is
configured with Origin.StorageType "pstore"; against any other backend the
origin does not register them and these commands report that plainly. A POSIX
origin's storage can be inspected with ordinary filesystem tools, which is why
it has no equivalent.

Consistency checking is deliberately absent here. Scanning an index while it is
being written produces findings indistinguishable from real problems, so
"pelican-server origin pstore fsck" remains an offline command.

These commands authenticate to the origin as an administrator. Run on the
origin host, no token is needed: a short-lived admin token is minted locally
with the origin's issuer key. Elsewhere -- or when that key is not readable --
pass --token pointing at a file holding an administrator token.`,
		SilenceUsage: true,
	}

	originIntrospectLsCmd = &cobra.Command{
		Use:          "ls [path]",
		Short:        "List a directory in the running origin's store",
		Args:         cobra.MaximumNArgs(1),
		RunE:         runIntrospectLs,
		SilenceUsage: true,
	}

	originIntrospectStatCmd = &cobra.Command{
		Use:          "stat <path>",
		Short:        "Show an object's metadata from the running origin",
		Args:         cobra.ExactArgs(1),
		RunE:         runIntrospectStat,
		SilenceUsage: true,
	}

	originIntrospectDigestCmd = &cobra.Command{
		Use:          "digest <path>",
		Short:        "Show an object's recorded checksums from the running origin",
		Args:         cobra.ExactArgs(1),
		RunE:         runIntrospectDigest,
		SilenceUsage: true,
	}

	originIntrospectUsageCmd = &cobra.Command{
		Use:          "usage",
		Short:        "Report how much of the store is in use",
		Args:         cobra.NoArgs,
		RunE:         runIntrospectUsage,
		SilenceUsage: true,
	}
)

func init() {
	originCmd.AddCommand(originIntrospectCmd)
	originIntrospectCmd.AddCommand(originIntrospectLsCmd)
	originIntrospectCmd.AddCommand(originIntrospectStatCmd)
	originIntrospectCmd.AddCommand(originIntrospectDigestCmd)
	originIntrospectCmd.AddCommand(originIntrospectUsageCmd)

	originIntrospectCmd.PersistentFlags().StringVar(&originIntrospectServer, "server", "",
		"Origin web URL (defaults to this host's Server.ExternalWebUrl)")
	originIntrospectCmd.PersistentFlags().StringVarP(&originIntrospectToken, "token", "t", "",
		"Path to admin token file (auto-generated from the local issuer key if not provided)")
	originIntrospectCmd.PersistentFlags().BoolVar(&originIntrospectJSON, "json", false,
		"Emit raw JSON instead of a table")
	originIntrospectLsCmd.Flags().IntVar(&originIntrospectLimit, "limit", 1000,
		"Maximum entries to return per request")
}

// storageEntry mirrors the API's entry representation.
type storageEntry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	IsDir    bool      `json:"isDir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	ETag     string    `json:"etag"`
}

type storageListResult struct {
	Backend string         `json:"backend"`
	Path    string         `json:"path"`
	Entries []storageEntry `json:"entries"`
	More    bool           `json:"more"`
}

type storageUsageResult struct {
	Backend       string `json:"backend"`
	UsedBytes     int64  `json:"usedBytes"`
	CapacityBytes int64  `json:"capacityBytes"`
}

type storageDigestResult struct {
	Backend string `json:"backend"`
	Path    string `json:"path"`
	Digest  string `json:"digest"`
}

// introspectGet calls the origin's storage API and decodes the result.
func introspectGet(cmd *cobra.Command, endpoint string, query url.Values, out any) error {
	if err := config.InitClient(); err != nil {
		return errors.Wrap(err, "failed to initialize configuration")
	}

	base := originIntrospectServer
	if base == "" {
		base = param.Server_ExternalWebUrl.GetString()
	}
	if base == "" {
		return errors.New("no origin URL; pass --server or configure Server.ExternalWebUrl")
	}
	target, err := url.Parse(strings.TrimSuffix(base, "/") + "/api/v1.0/origin/storage/pstore" + endpoint)
	if err != nil {
		return errors.Wrap(err, "the origin URL is not valid")
	}
	if query != nil {
		target.RawQuery = query.Encode()
	}

	// Standard admin-token discovery: read --token if given, otherwise mint a
	// short-lived one with the local issuer key.  Same helper (and so the same
	// contract) as the other administrative CLIs.
	tok, err := fetchOrGenerateWebAPIAdminToken(base, originIntrospectToken)
	if err != nil {
		return errors.Wrap(err, "failed to obtain an administrator token")
	}

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := config.GetClient().Do(req)
	if err != nil {
		return errors.Wrapf(err, "cannot reach the origin at %s", base)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read the origin's response")
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// Distinguish "no such object" from "this origin has no storage API",
		// which is what a non-pstore origin returns for every route here.
		var apiResp server_structs.SimpleApiResp
		if json.Unmarshal(body, &apiResp) == nil && apiResp.Msg != "" {
			return errors.New(apiResp.Msg)
		}
		return errors.New("the origin has no storage introspection API; " +
			"these commands require Origin.StorageType \"pstore\"")
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("the origin rejected the token; these commands require an administrator, " +
			"and the locally-minted token is only accepted by the origin whose issuer key signed it")
	default:
		var apiResp server_structs.SimpleApiResp
		if json.Unmarshal(body, &apiResp) == nil && apiResp.Msg != "" {
			return errors.Errorf("the origin returned %d: %s", resp.StatusCode, apiResp.Msg)
		}
		return errors.Errorf("the origin returned %d", resp.StatusCode)
	}

	if originIntrospectJSON {
		fmt.Println(string(body))
		return errSuppressOutput
	}
	return errors.Wrap(json.Unmarshal(body, out), "the origin's response could not be decoded")
}

// errSuppressOutput signals that --json already printed everything.
var errSuppressOutput = errors.New("output already written")

func introspectPathArg(args []string) string {
	if len(args) == 0 {
		return "/"
	}
	if !strings.HasPrefix(args[0], "/") {
		return "/" + args[0]
	}
	return args[0]
}

// introspectEscapePath renders an object path as URL path segments.
//
// Object names are arbitrary bytes as far as the store is concerned, and a
// path pasted straight into a URL stops being a path the moment it contains a
// character the URL grammar claims.  A '?' turns the rest of the name into a
// query string -- which the request then overwrites with its own -- so
// `stat "/data/f?v=1"` would quietly stat `/data/f` and report on the wrong
// object; '#' truncates the name the same way.  Escaping per segment (rather
// than escaping the whole path, which would also escape the separators) keeps
// the structure and neutralises the content.
func introspectEscapePath(objectPath string) string {
	var b strings.Builder
	for _, segment := range strings.Split(objectPath, "/") {
		if segment == "" {
			continue
		}
		b.WriteByte('/')
		b.WriteString(url.PathEscape(segment))
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

func runIntrospectLs(cmd *cobra.Command, args []string) error {
	path := introspectPathArg(args)
	query := url.Values{}
	query.Set("limit", fmt.Sprint(originIntrospectLimit))

	var result storageListResult
	if err := introspectGet(cmd, "/ls"+introspectEscapePath(path), query, &result); err != nil {
		if errors.Is(err, errSuppressOutput) {
			return nil
		}
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "MODE\tSIZE\tMODIFIED\tNAME")
	for _, e := range result.Entries {
		kind, size := "-", utils.HumanBytes(e.Size)
		name := e.Name
		if e.IsDir {
			kind, size = "d", "-"
			name += "/"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", kind, size, e.Modified.Format(time.RFC3339), name)
	}
	if result.More {
		fmt.Fprintf(w, "\n(more entries; raise --limit or page with the API's \"after\")\n")
	}
	return nil
}

func runIntrospectStat(cmd *cobra.Command, args []string) error {
	var e storageEntry
	if err := introspectGet(cmd, "/stat"+introspectEscapePath(introspectPathArg(args)), nil, &e); err != nil {
		if errors.Is(err, errSuppressOutput) {
			return nil
		}
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "Path:\t%s\n", e.Path)
	if e.IsDir {
		fmt.Fprintf(w, "Type:\tdirectory\n")
	} else {
		fmt.Fprintf(w, "Type:\tobject\n")
		fmt.Fprintf(w, "Size:\t%d (%s)\n", e.Size, utils.HumanBytes(e.Size))
		if e.ETag != "" {
			fmt.Fprintf(w, "ETag:\t%s\n", e.ETag)
		}
	}
	fmt.Fprintf(w, "Modified:\t%s\n", e.Modified.Format(time.RFC3339))
	return nil
}

func runIntrospectDigest(cmd *cobra.Command, args []string) error {
	var result storageDigestResult
	if err := introspectGet(cmd, "/digest"+introspectEscapePath(introspectPathArg(args)), nil, &result); err != nil {
		if errors.Is(err, errSuppressOutput) {
			return nil
		}
		return err
	}
	if result.Digest == "" {
		return errors.Errorf("no checksums recorded for %s", result.Path)
	}
	for _, entry := range strings.Split(result.Digest, ", ") {
		name, value, _ := strings.Cut(entry, "=")
		fmt.Printf("%s\t%s\n", name, value)
	}
	return nil
}

func runIntrospectUsage(cmd *cobra.Command, args []string) error {
	var result storageUsageResult
	if err := introspectGet(cmd, "/usage", nil, &result); err != nil {
		if errors.Is(err, errSuppressOutput) {
			return nil
		}
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "Backend:\t%s\n", result.Backend)
	fmt.Fprintf(w, "Used:\t%s\n", utils.HumanBytes(result.UsedBytes))
	if result.CapacityBytes > 0 {
		fmt.Fprintf(w, "Capacity:\t%s (%.1f%% used)\n", utils.HumanBytes(result.CapacityBytes),
			100*float64(result.UsedBytes)/float64(result.CapacityBytes))
	} else {
		fmt.Fprintf(w, "Capacity:\tunbounded\n")
	}
	return nil
}
