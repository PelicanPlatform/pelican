//go:build cgo

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
	"regexp"
	"strings"
	"testing"
)

// This file pins the exported C ABI against the header this library publishes,
// so a Go-side signature can never silently drift from what external consumers
// compile against. Drift is not a compile error on either side -- the XRootD
// purge plugin binds by symbol name at load time -- it is a wrong-arity call
// that shifts every subsequent argument, so a bool lands where a pointer was
// expected and the library stores through it. That is an immediate SIGSEGV
// inside xrootd with no diagnostic.
//
// The expectations are *parsed from* include/lotman/lotman.h rather than
// transcribed into a table here. That header is the file the RPM installs at
// /usr/include/lotman/lotman.h and the one xrootd-lotman compiles against, so
// making it the single source of truth removes the failure mode a second copy
// creates: a table that agrees with the Go code while the shipped header, which
// is what actually governs callers, says something else.
//
// Parameter *names* are free to differ; the type sequence and arity are the
// contract. `const` is dropped because it does not affect the calling
// convention.

// headerPath is the published interface, relative to this package directory.
const headerPath = "include/lotman/lotman.h"

var (
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`//[^\n]*`)
	// A declaration is "<return type> lotman_<name>(<args>);". Argument lists
	// in this header contain no nested parentheses.
	declRe = regexp.MustCompile(`(?s)([A-Za-z_][A-Za-z0-9_ \t\n*]*?)(lotman_[a-z0-9_]+)\s*\(([^;()]*)\)\s*;`)
)

// abiVariantPrototypes are the entry points whose shape depends on the selected
// ABI build tag.
//
// The published header describes the current (v0.1.0) ABI, which is what the
// package ships and what export_api_v1.go must match -- so that file is checked
// against the header like every other export. The legacy variant deliberately
// does *not* match the header: it re-exports the older lotman v0.0.4 signatures
// for a site whose deployed libXrdPurgeLotMan was compiled against them, and it
// is built only by hand (`make lotman-shared LOTMAN_ABI=legacy`), never
// packaged. Its expectations therefore have to be stated here, transcribed from
// src/lotman.h at tag v0.0.4 in https://github.com/PelicanPlatform/lotman.
//
// Both export files are parsed on every run even though only one is compiled,
// so the legacy variant -- which no CI job builds -- is still checked.
var abiVariantPrototypes = map[string]map[string]string{
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

// cBaseTypes are the type keywords the published header is allowed to use. An
// unlisted one fails the test rather than being normalized away, because a type
// this test does not understand is a type it cannot check.
var cBaseTypes = map[string]bool{
	"char": true, "int": true, "bool": true, "int64_t": true, "void": true,
}

func TestExportedABIMatchesPublishedHeader(t *testing.T) {
	header := parseHeaderPrototypes(t)

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
			source := headerPath
			want, ok := abiVariantPrototypes[filepath.Base(file)][name]
			if ok {
				source = "the lotman v0.0.4 ABI"
			} else {
				want, ok = header[name]
			}
			if !ok {
				t.Errorf("%s: exported by %s but not declared in %s; "+
					"add it to the published header so consumers can call it", name, file, headerPath)
				continue
			}
			seen[file+":"+name] = true

			got := cSignature(t, fset, src, fn)
			if got != want {
				t.Errorf("%s (%s):\n   exports: %s\n  declared: %s (%s)\n"+
					"An arity or type mismatch shifts the caller's arguments and faults inside the host process.",
					name, file, got, want, source)
			}
		}
	}

	// Every declaration in the published header must actually be exported, or
	// a consumer links against a symbol this library does not define.
	for name := range header {
		found := false
		for k := range seen {
			if strings.HasSuffix(k, ":"+name) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is declared in %s but is not exported by this library", name, headerPath)
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

// parseHeaderPrototypes reads the published header and returns each declared
// function in the same canonical "ret(param, ...)" form cSignature produces.
func parseHeaderPrototypes(t *testing.T) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("read %s: %v", headerPath, err)
	}
	src := lineCommentRe.ReplaceAllString(blockCommentRe.ReplaceAllString(string(raw), " "), " ")

	protos := map[string]string{}
	for _, m := range declRe.FindAllStringSubmatch(src, -1) {
		ret, name, args := m[1], m[2], m[3]
		var params []string
		for _, arg := range strings.Split(args, ",") {
			if strings.TrimSpace(arg) == "" {
				continue
			}
			params = append(params, normalizeCType(t, name, arg))
		}
		protos[name] = normalizeCType(t, name, ret) + "(" + strings.Join(params, ", ") + ")"
	}
	if len(protos) == 0 {
		t.Fatalf("no function declarations found in %s -- the header's shape changed and this test is no longer checking anything", headerPath)
	}
	return protos
}

// normalizeCType reduces a C declarator to "<base><spaced stars>", dropping the
// parameter name, `const`, and all whitespace variation.
func normalizeCType(t *testing.T, fn, decl string) string {
	t.Helper()

	stars := strings.Count(decl, "*")
	cleaned := strings.ReplaceAll(strings.ReplaceAll(decl, "*", " "), "const", " ")
	for _, field := range strings.Fields(cleaned) {
		if cBaseTypes[field] {
			if stars == 0 {
				return field
			}
			return field + " " + strings.Repeat("*", stars)
		}
	}
	t.Errorf("%s: cannot normalize C type %q from %s -- add its base type to cBaseTypes", fn, strings.TrimSpace(decl), headerPath)
	return strings.TrimSpace(decl)
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
