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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file pins the exported C ABI against the interface libLotMan publishes,
// so a Go-side signature can never silently drift from the header external
// consumers compile against. Drift is not a compile error on either side -- the
// XRootD purge plugin binds by symbol name at load time -- it is a wrong-arity
// call that shifts every subsequent argument, so a bool lands where a pointer
// was expected and the library stores through it. That is an immediate SIGSEGV
// inside xrootd with no diagnostic.
//
// The expectations below are transcribed from src/lotman.h in
// https://github.com/PelicanPlatform/lotman (v0.1.0). Parameter *names* are free
// to differ; the type sequence and arity are the contract. `const` is dropped
// because it does not affect the calling convention.
var upstreamPrototypes = map[string]string{
	// lifecycle
	"lotman_add_lot":               "int(char *, char **)",
	"lotman_update_lot":            "int(char *, char **)",
	"lotman_add_to_lot":            "int(char *, char **)",
	"lotman_remove_lot":            "int(char *, bool, bool, bool, bool, char **)",
	"lotman_remove_lots_recursive": "int(char *, char **)",
	"lotman_rm_parents_from_lot":   "int(char *, char **)",
	"lotman_rm_paths_from_lots":    "int(char *, char **)",
	"lotman_reclaim_lot":           "int(char *, int64_t, char *, char **)",

	// predicates
	"lotman_lot_exists": "int(char *, char **)",
	"lotman_is_root":    "int(char *, char **)",

	// hierarchy / listing
	"lotman_get_owners":         "int(char *, bool, char ***, char **)",
	"lotman_get_parent_names":   "int(char *, bool, bool, char ***, char **)",
	"lotman_get_children_names": "int(char *, bool, bool, char ***, char **)",
	"lotman_list_all_lots":      "int(char ***, char **)",

	// path resolution. Note lotman_get_lots_for_path returns a single JSON
	// array string (char **), not a string list (char ***), and takes an
	// include_reclaimed flag between the window bounds and the output.
	"lotman_get_lots_from_dir": "int(char *, bool, int64_t, char ***, char **)",
	"lotman_get_lots_for_path": "int(char *, bool, int64_t, int64_t, bool, char **, char **)",

	// documents / usage
	"lotman_get_lot_as_json":        "int(char *, bool, char **, char **)",
	"lotman_get_lot_dirs":           "int(char *, bool, char **, char **)",
	"lotman_get_lot_usage":          "int(char *, char **, char **)",
	"lotman_get_policy_attributes":  "int(char *, char **, char **)",
	"lotman_get_available_capacity": "int(char *, int64_t, int64_t, char **, char **)",
	"lotman_update_lot_usage":       "int(char *, bool, char **)",

	// context
	"lotman_set_context_str": "int(char *, char *, char **)",
	"lotman_get_context_str": "int(char *, char **, char **)",
	"lotman_set_context_int": "int(char *, int, char **)",
	"lotman_get_context_int": "int(char *, int *, char **)",

	// memory / metadata
	"lotman_free_string_list": "void(char **)",
	"lotman_version":          "char *()",
}

// abiVariantPrototypes are the entry points whose shape depends on the selected
// ABI build tag. Only one variant is compiled at a time, but both source files
// are parsed here, so both are checked on every run -- the legacy variant is
// otherwise built by no CI job at all.
var abiVariantPrototypes = map[string]map[string]string{
	"export_api_v1.go": {
		"lotman_get_lots_past_exp":       "int(int64_t, bool, bool, char ***, char **)",
		"lotman_get_lots_past_del":       "int(int64_t, bool, bool, char ***, char **)",
		"lotman_get_lots_past_opp":       "int(bool, bool, bool, char ***, bool, char **)",
		"lotman_get_lots_past_ded":       "int(bool, bool, bool, char ***, bool, char **)",
		"lotman_get_lots_past_obj":       "int(bool, bool, bool, char ***, bool, char **)",
		"lotman_update_lot_usage_by_dir": "int(char *, bool, int64_t, char **)",
	},
	"export_api_legacy.go": {
		"lotman_get_lots_past_exp":       "int(bool, char ***, char **)",
		"lotman_get_lots_past_del":       "int(bool, char ***, char **)",
		"lotman_get_lots_past_opp":       "int(bool, bool, char ***, char **)",
		"lotman_get_lots_past_ded":       "int(bool, bool, char ***, char **)",
		"lotman_get_lots_past_obj":       "int(bool, bool, char ***, char **)",
		"lotman_update_lot_usage_by_dir": "int(char *, bool, char **)",
	},
}

// cgoToC translates a cgo type expression into the C type it compiles to.
var cgoToC = map[string]string{
	"*C.char":   "char *",
	"**C.char":  "char **",
	"***C.char": "char ***",
	"C._Bool":   "bool",
	"C.int64_t": "int64_t",
	"C.int":     "int",
	"*C.int":    "int *",
}

func TestExportedABIMatchesUpstreamHeader(t *testing.T) {
	files, err := filepath.Glob("export*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("globbing export files: %v (found %d)", err, len(files))
	}

	seen := map[string]bool{}
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil {
				continue
			}
			isExport := false
			for _, c := range fn.Doc.List {
				if strings.HasPrefix(c.Text, "//export ") {
					isExport = true
				}
			}
			if !isExport {
				continue
			}

			name := fn.Name.Name
			want, ok := upstreamPrototypes[name]
			if !ok {
				want, ok = abiVariantPrototypes[filepath.Base(file)][name]
			}
			if !ok {
				t.Errorf("%s: exported by %s but absent from the upstream prototype table; "+
					"add it (and confirm it exists in lotman.h) so the ABI stays pinned", name, file)
				continue
			}
			seen[file+":"+name] = true

			got := cSignature(t, fset, src, fn)
			if got != want {
				t.Errorf("%s (%s):\n   exports: %s\n  upstream: %s\n"+
					"An arity or type mismatch shifts the caller's arguments and faults inside the host process.",
					name, file, got, want)
			}
		}
	}

	// Every prototype in the table must actually be exported.
	for name := range upstreamPrototypes {
		found := false
		for k := range seen {
			if strings.HasSuffix(k, ":"+name) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is in the upstream prototype table but is not exported by this library", name)
		}
	}
	for file, protos := range abiVariantPrototypes {
		for name := range protos {
			if !seen[file+":"+name] {
				t.Errorf("%s is expected in %s but was not found there", name, file)
			}
		}
	}
}

// nodeText returns the exact source text of a node. Positions are fileset
// positions, not byte offsets, so they must be resolved through the fileset.
func nodeText(fset *token.FileSet, src []byte, node ast.Node) string {
	return string(src[fset.Position(node.Pos()).Offset:fset.Position(node.End()).Offset])
}

// cSignature renders a cgo function declaration as its C prototype shape,
// "ret(param, param, ...)", using types only.
func cSignature(t *testing.T, fset *token.FileSet, src []byte, fn *ast.FuncDecl) string {
	t.Helper()

	translate := func(node ast.Node) string {
		expr := nodeText(fset, src, node)
		if c, ok := cgoToC[expr]; ok {
			return c
		}
		t.Errorf("%s: unmapped cgo type %q -- add it to cgoToC", fn.Name.Name, expr)
		return expr
	}

	ret := "void"
	if fn.Type.Results != nil && len(fn.Type.Results.List) == 1 {
		ret = translate(fn.Type.Results.List[0].Type)
	}

	var params []string
	if fn.Type.Params != nil {
		for _, p := range fn.Type.Params.List {
			c := translate(p.Type)
			// A group like "recursive, getSelf C._Bool" declares one type for
			// several parameters.
			n := len(p.Names)
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				params = append(params, c)
			}
		}
	}
	return ret + "(" + strings.Join(params, ", ") + ")"
}
