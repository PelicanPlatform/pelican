//go:build client

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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	duCmd = &cobra.Command{
		Use:   "du <object> [<object>...]",
		Short: "Estimate storage usage under one or more federation paths",
		Long: `Report the total size of every collection under the given federation
path(s), analogous to the Unix "du" utility.

By default, each collection encountered during the recursive walk is printed
with its cumulative size (bytes plus the number of objects and subcollections
it contains) followed by the root of the walk itself. Use --max-depth to trim
the output to a limited number of levels below the argument; --max-depth 0
prints only the argument.

Directory sizes are always cumulative -- every object counts toward every
ancestor collection up to the argument.  Collections themselves have no
intrinsic size, so their totals reflect only the objects they contain.`,
		RunE: duMain,
	}
)

func init() {
	flagSet := duCmd.Flags()
	// Reclaim -h for --human-readable, matching GNU du's muscle memory. Cobra's
	// InitDefaultHelpFlag only registers --help/-h when Lookup("help") returns
	// nil, so pre-registering --help here (without a shorthand) lets us bind
	// -h to a real command flag without a panic on startup.
	flagSet.Bool("help", false, "help for du")
	flagSet.StringP("token", "t", "", "Token file to use for authenticated listings")
	flagSet.StringP("collections-url", "", "", "URL to use for collection listing, overriding the director's response")
	flagSet.BoolP("human-readable", "h", false, "Print sizes in a human-readable format (KiB, MiB, GiB, ... using IEC binary units)")
	flagSet.BoolP("json", "j", false, "Print results in JSON format")
	flagSet.Int("max-depth", -1, "Print the total for a collection only if it is at most N levels below an argument. -1 means unlimited.")
	flagSet.Bool("count", false, "Include object and collection counts alongside each size")

	objectCmd.AddCommand(duCmd)
}

// dirTotals accumulates cumulative statistics for a single collection path
// (bytes contributed by every descendant object, plus counts).
type dirTotals struct {
	path        string
	depth       int // depth relative to the walked argument's root (0 = root)
	bytes       int64
	objects     int64
	collections int64
}

// duReport is the JSON-marshalable per-collection record emitted with --json.
type duReport struct {
	Path        string `json:"path"`
	Bytes       int64  `json:"bytes"`
	Objects     int64  `json:"objects,omitempty"`
	Collections int64  `json:"collections,omitempty"`
}

func duMain(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if err := config.InitClient(); err != nil {
		log.Errorln(err)
		if client.IsRetryable(err) {
			os.Exit(11)
		}
		os.Exit(1)
	}

	if len(args) == 0 {
		log.Errorln("no path provided")
		if helpErr := cmd.Help(); helpErr != nil {
			log.Errorln("failed to print help:", helpErr)
		}
		os.Exit(1)
	}

	tokenLocation, _ := cmd.Flags().GetString("token")
	collectionsUrl, _ := cmd.Flags().GetString("collections-url")
	human, _ := cmd.Flags().GetBool("human-readable")
	asJSON, _ := cmd.Flags().GetBool("json")
	maxDepth, _ := cmd.Flags().GetInt("max-depth")
	withCount, _ := cmd.Flags().GetBool("count")

	// The listing walks the full tree; --max-depth only controls what we PRINT.
	// Passing WithDepth to the client would cut the walk short and hide bytes
	// that live deeper than maxDepth from the ancestor totals, which is the
	// opposite of what du should do.
	options := []client.TransferOption{
		client.WithTokenLocation(tokenLocation),
		client.WithCollectionsUrl(collectionsUrl),
		client.WithRecursive(true),
	}

	var reports [][]duReport
	for _, arg := range args {
		reports = append(reports, duForRoot(ctx, arg, maxDepth, options))
	}

	if asJSON {
		// Flatten into a single JSON array of per-collection records so
		// downstream tooling sees one document regardless of arg count.
		flat := []duReport{}
		for _, rs := range reports {
			flat = append(flat, rs...)
		}
		enc, err := json.Marshal(flat)
		if err != nil {
			return errors.Wrap(err, "failed to marshal du output")
		}
		fmt.Println(string(enc))
		return nil
	}

	// Text mode: one tabwriter for all arguments so columns align across them.
	w := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)
	for _, rs := range reports {
		for _, r := range rs {
			fmt.Fprintln(w, formatDuLine(r, human, withCount))
		}
	}
	return w.Flush()
}

// duForRoot walks a single argument path and produces the ordered list of
// per-collection reports for it (deepest subcollections first, argument root
// last -- the same convention Unix du uses). Errors are logged and cause an
// empty slice to be returned for that argument; other arguments still get
// processed.
func duForRoot(ctx context.Context, arg string, maxDepth int, options []client.TransferOption) []duReport {
	root := normalizeCollectionPath(arg)
	// Every entry maps a collection path to its cumulative totals. The root
	// itself gets an entry so it's always reported, even for empty prefixes.
	totals := map[string]*dirTotals{
		root: {path: root, depth: 0},
	}

	err := client.DoListStream(ctx, arg, func(info client.FileInfo) error {
		// Normalize to an absolute-looking path so ancestry math is trivial.
		p := normalizeEntryPath(info.Name)
		if info.IsCollection {
			// Ensure the collection has an entry, but its own size is 0 --
			// only descendant objects contribute bytes.
			if _, ok := totals[p]; !ok {
				totals[p] = &dirTotals{path: p, depth: depthFromRoot(root, p)}
			}
			// Every ancestor (up through the root) gains a collection count.
			forEachAncestorInclusive(p, root, func(anc string) {
				t, ok := totals[anc]
				if !ok {
					t = &dirTotals{path: anc, depth: depthFromRoot(root, anc)}
					totals[anc] = t
				}
				if anc != p {
					// Don't double-count self as its own subcollection.
					t.collections++
				}
			})
			return nil
		}
		// Object: contribute Size + one to every ancestor collection up to the root.
		forEachAncestorInclusive(path.Dir(p), root, func(anc string) {
			t, ok := totals[anc]
			if !ok {
				t = &dirTotals{path: anc, depth: depthFromRoot(root, anc)}
				totals[anc] = t
			}
			t.bytes += info.Size
			t.objects++
		})
		return nil
	}, options...)
	if err != nil {
		log.Errorf("Failed to compute du for %q: %v", arg, err)
		return nil
	}

	// Emit ordering: deepest first, then alphabetical within a depth level, so
	// the argument root is always the last line for that argument -- matching
	// `du <path>`'s convention of ending with the total for the argument.
	keys := make([]string, 0, len(totals))
	for k := range totals {
		if maxDepth >= 0 && totals[k].depth > maxDepth {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if totals[keys[i]].depth != totals[keys[j]].depth {
			return totals[keys[i]].depth > totals[keys[j]].depth
		}
		return keys[i] < keys[j]
	})

	// Rewrite the reported path back to what the user asked for when the entry
	// corresponds to the argument root itself. This preserves scheme/host from
	// the argument (e.g., "osdf:///a" instead of "/a") without complicating
	// the ancestry math above.
	rootReport := arg
	out := make([]duReport, 0, len(keys))
	for _, k := range keys {
		t := totals[k]
		reportPath := t.path
		if k == root {
			reportPath = rootReport
		}
		out = append(out, duReport{
			Path:        reportPath,
			Bytes:       t.bytes,
			Objects:     t.objects,
			Collections: t.collections,
		})
	}
	return out
}

// formatDuLine produces a single tab-separated line for the -h/-j-off case.
// Layout: "<size>  [<objects>  <collections>  ]<path>" so that when tabwriter
// aligns columns the path column is always the last one.
func formatDuLine(r duReport, human, withCount bool) string {
	var size string
	if human {
		size = humanize.IBytes(uint64(r.Bytes))
	} else {
		size = strconv.FormatInt(r.Bytes, 10)
	}
	if withCount {
		return strings.Join([]string{
			size,
			strconv.FormatInt(r.Objects, 10),
			strconv.FormatInt(r.Collections, 10),
			r.Path,
		}, "\t")
	}
	return size + "\t" + r.Path
}

// normalizeCollectionPath strips scheme/host and trailing slashes from a
// federation URL so ancestry math treats the argument as a plain path.
func normalizeCollectionPath(remote string) string {
	// Trim scheme://host and anything after '?' so path.Dir sees only the
	// object path itself. We don't need a full URL parse because we just want
	// the path suffix.
	rest := remote
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			rest = rest[slash:]
		} else {
			rest = "/"
		}
	}
	if q := strings.Index(rest, "?"); q >= 0 {
		rest = rest[:q]
	}
	rest = strings.TrimRight(rest, "/")
	if rest == "" {
		return "/"
	}
	return rest
}

// normalizeEntryPath strips a trailing slash from a listing entry name so
// keys compare as plain absolute paths.
func normalizeEntryPath(name string) string {
	if name == "/" {
		return name
	}
	return strings.TrimRight(name, "/")
}

// depthFromRoot returns how many path segments separate p from root. Callers
// pass the argument's normalized root; p is a normalized descendant (or the
// root itself, which is depth 0). Returns 0 when p == root, else the number
// of "/"-separated segments strictly below root.
func depthFromRoot(root, p string) int {
	if p == root {
		return 0
	}
	rel := strings.TrimPrefix(p, root)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return 0
	}
	return strings.Count(rel, "/") + 1
}

// forEachAncestorInclusive walks from p up to root (inclusive) and calls fn on
// each ancestor collection. If p is at or above root, only root is visited.
func forEachAncestorInclusive(p, root string, fn func(string)) {
	if p == "" || p == "." {
		fn(root)
		return
	}
	// Stop when we've stepped above root to avoid attributing bytes to
	// parents outside the walk's scope.
	for {
		fn(p)
		if p == root {
			return
		}
		parent := path.Dir(p)
		if parent == p || len(parent) < len(root) {
			// Prevent runaway climbs when the argument root isn't a strict
			// prefix of p (should not happen in practice, but be defensive).
			if p != root {
				fn(root)
			}
			return
		}
		p = parent
	}
}
