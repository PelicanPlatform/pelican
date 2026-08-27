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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
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

By default, every collection encountered during the recursive walk is printed
with its cumulative byte total (plus the number of objects and nested
collections it holds) followed by the argument itself. Use --max-depth to trim
the output to a limited number of levels below the argument; --max-depth 0
prints only the argument.

Sizes are always cumulative -- every object counts toward every enclosing
collection up to the argument. Collections themselves have no intrinsic size,
so their totals reflect only the objects they contain.

Unreadable subtrees encountered during the walk are reported to stderr and
skipped; the totals still reflect every object that was reachable. If any
subtree failed, du exits with a non-zero status.`,
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
	flagSet.BoolP("summarize", "s", false, "Print only the total for each argument (equivalent to --max-depth 0)")
	flagSet.Int("max-depth", -1, "Print the total for a collection only if it is at most N levels below an argument. -1 means unlimited.")
	flagSet.Bool("count", false, "Include object and nested-collection counts alongside each size")

	// -s and --max-depth are two spellings of the same idea; complain rather
	// than silently favor one.
	duCmd.MarkFlagsMutuallyExclusive("summarize", "max-depth")

	objectCmd.AddCommand(duCmd)
}

// collectionTotals accumulates cumulative statistics for a single collection
// path (bytes contributed by every reachable descendant object, plus counts
// of descendant objects and nested collections).
type collectionTotals struct {
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
	summarize, _ := cmd.Flags().GetBool("summarize")
	withCount, _ := cmd.Flags().GetBool("count")
	if summarize {
		// -s is a familiar shorthand from GNU du. Mutual exclusion with
		// --max-depth is enforced at flag-registration time, so seeing
		// summarize here is a plain "print only the argument total".
		maxDepth = 0
	}

	// The listing walks the full tree; --max-depth only controls what we PRINT.
	// Passing WithDepth to the client would cut the walk short and hide bytes
	// that live deeper than maxDepth from the enclosing-collection totals, which
	// is the opposite of what du should do.
	options := []client.TransferOption{
		client.WithTokenLocation(tokenLocation),
		client.WithCollectionsUrl(collectionsUrl),
		client.WithRecursive(true),
	}

	// One accumulator per argument; each is only touched by the callback
	// invocations for its own root (WalkMany's per-root callback is serialized
	// per walk), so the per-root map itself needs no lock. The failure flag is
	// shared across all callbacks, so it needs one.
	perRoot := make([]*duAccumulator, len(args))
	for i, arg := range args {
		perRoot[i] = newDuAccumulator(arg)
	}
	indexByRoot := make(map[string]int, len(args))
	for i, arg := range args {
		indexByRoot[arg] = i
	}

	var (
		failMu     sync.Mutex
		failed     = make(map[string]bool, len(args))
		anyFailure bool
	)
	markFailed := func(arg string) {
		failMu.Lock()
		defer failMu.Unlock()
		failed[arg] = true
		anyFailure = true
	}

	// Walks are dispatched under a semaphore inside WalkMany; passing 0 lets
	// it default to param.Client_WorkerCount. With a single argument the
	// concurrency cap collapses to 1 and this behaves exactly like Walk.
	walkErr := client.WalkMany(ctx, args, 0, func(root string, info client.FileInfo, emitErr error) error {
		acc := perRoot[indexByRoot[root]]
		if emitErr != nil {
			log.Errorf("du: cannot read %q: %v", info.Name, emitErr)
			markFailed(root)
			return nil
		}
		acc.observe(info)
		return nil
	}, options...)
	if walkErr != nil {
		// WalkMany returns errors.Join across roots. Individual roots' failures
		// are already logged inside WalkMany's per-root wrapping; anyFailure
		// captures whether at least one walk did not complete.
		log.Errorf("du: %v", walkErr)
		anyFailure = true
		// A walk that never called our callback (e.g. director lookup failed
		// up front) means we cannot attribute the failure to a specific arg
		// via emitErr paths -- mark every arg whose accumulator is still
		// empty of any observation.
		for _, arg := range args {
			if !perRoot[indexByRoot[arg]].observed {
				markFailed(arg)
			}
		}
	}

	reports := make([][]duReport, len(args))
	for i, acc := range perRoot {
		reports[i] = acc.report(maxDepth)
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
	} else {
		// Text mode: one tabwriter for all arguments so columns align.
		w := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)
		for _, rs := range reports {
			for _, r := range rs {
				fmt.Fprintln(w, formatDuLine(r, human, withCount))
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}

	if anyFailure {
		// Match GNU du: totals were still printed, but the exit status reflects
		// that at least one subtree could not be read.
		os.Exit(1)
	}
	return nil
}

// duAccumulator holds the per-argument state that observe() mutates as
// listing entries arrive and that report() drains into the ordered emit list.
// One accumulator exists per CLI argument; callers must not share an
// accumulator across goroutines (each root's WalkMany callback is serialized).
type duAccumulator struct {
	arg      string
	root     string
	totals   map[string]*collectionTotals
	observed bool // set on first observation; used to distinguish "walk never called us" from "walk saw nothing"
}

func newDuAccumulator(arg string) *duAccumulator {
	root := normalizeCollectionPath(arg)
	return &duAccumulator{
		arg:    arg,
		root:   root,
		totals: map[string]*collectionTotals{root: {path: root, depth: 0}},
	}
}

func (a *duAccumulator) ensure(p string) *collectionTotals {
	t, ok := a.totals[p]
	if !ok {
		t = &collectionTotals{path: p, depth: depthFromRoot(a.root, p)}
		a.totals[p] = t
	}
	return t
}

// observe folds a single successfully-listed entry into the accumulator.
// Called from WalkMany's callback in the per-root goroutine, so no locking is
// required within the accumulator itself.
func (a *duAccumulator) observe(info client.FileInfo) {
	a.observed = true
	// Normalize to an absolute, //-free path so ancestor math is stable
	// regardless of how the origin formats entries.
	p := normalizeEntryPath(info.Name)
	if info.IsCollection {
		a.ensure(p)
		// Every enclosing collection (up through the root) gains one toward
		// its nested-collection count -- but not this collection itself.
		forEachAncestorInclusive(p, a.root, func(anc string) {
			t := a.ensure(anc)
			if anc != p {
				t.collections++
			}
		})
		return
	}
	// Object: contribute Size + one to every enclosing collection up to root.
	forEachAncestorInclusive(path.Dir(p), a.root, func(anc string) {
		t := a.ensure(anc)
		t.bytes += info.Size
		t.objects++
	})
}

// report produces the ordered per-collection reports for this argument, honoring
// maxDepth. Order is deepest-first, alphabetical within a depth level, so the
// argument root always lands last -- matching Unix du's convention.
func (a *duAccumulator) report(maxDepth int) []duReport {
	keys := make([]string, 0, len(a.totals))
	for k := range a.totals {
		if maxDepth >= 0 && a.totals[k].depth > maxDepth {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if a.totals[keys[i]].depth != a.totals[keys[j]].depth {
			return a.totals[keys[i]].depth > a.totals[keys[j]].depth
		}
		return keys[i] < keys[j]
	})

	out := make([]duReport, 0, len(keys))
	for _, k := range keys {
		t := a.totals[k]
		reportPath := t.path
		if k == a.root {
			// Echo back what the caller wrote (preserves scheme/host) instead
			// of the normalized bare path.
			reportPath = a.arg
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

// formatDuLine produces a single tab-separated line for the non-JSON case.
// Layout: "<size>  [<objects>  <collections>  ]<path>" so tabwriter can align
// the path column as the final one.
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

// normalizeCollectionPath strips scheme/host and query string, collapses
// duplicate slashes, and trims trailing slashes so ancestor math is stable
// regardless of how the user wrote the argument. Returns "/" for empty or
// "//"-only inputs so the invariants elsewhere (ancestry stops at root) hold.
//
// path.Clean guarantees no doubled slashes appear in downstream keys, which
// matters because listing entries could otherwise carry "//" from a poorly
// normalized origin.
func normalizeCollectionPath(remote string) string {
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
	if rest == "" {
		return "/"
	}
	cleaned := path.Clean(rest)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

// normalizeEntryPath cleans a listing entry name so paths compare consistently
// with normalizeCollectionPath output. Doubled slashes ("//"), trailing "/"
// on non-root entries, and "." are all normalized out; the root path stays
// as "/".
func normalizeEntryPath(name string) string {
	if name == "" || name == "/" {
		return "/"
	}
	cleaned := path.Clean(name)
	if cleaned == "." {
		return "/"
	}
	return cleaned
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
// each enclosing collection. If p is at or above root, only root is visited.
func forEachAncestorInclusive(p, root string, fn func(string)) {
	if p == "" || p == "." {
		fn(root)
		return
	}
	// Stop when we've stepped above root to avoid attributing bytes to
	// enclosing collections outside the walk's scope.
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
