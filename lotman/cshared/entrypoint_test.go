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

// TestPanicGuardConvertsPanicToError pins the behaviour that keeps a Go panic
// from taking down the host process. In -buildmode=c-shared a panic unwinding
// out of an //export function terminates the process, which for the purge plugin
// is xrootd; guard() must turn it into the library's generic -1 return instead.
func TestPanicGuardConvertsPanicToError(t *testing.T) {
	rc, msg := panicGuardProbeGo()
	if rc != -1 {
		t.Errorf("panicking entry point returned rc=%d, want -1", rc)
	}
	if !strings.Contains(msg, "probe") {
		t.Errorf("err_msg = %q, want it to carry the panic value", msg)
	}
}

// TestOutParamsClearedOnFailure covers the other half: consumers free `output`
// without first checking the return code, so a failing entry point must leave
// NULL there rather than the caller's uninitialised stack value.
func TestOutParamsClearedOnFailure(t *testing.T) {
	resetStateForTest()
	defer resetStateForTest()

	// No lot_home set, so manager() fails and every entry point takes its
	// earliest error return.
	if rc, cleared := listOutClearedOnFailureGo(); rc != -1 || !cleared {
		t.Errorf("list-out entry point: rc=%d cleared=%v; want -1, true", rc, cleared)
	}
	if rc, cleared := strOutClearedOnFailureGo(); rc != -1 || !cleared {
		t.Errorf("string-out entry point: rc=%d cleared=%v; want -1, true", rc, cleared)
	}
}

// TestEveryExportIsGuarded is a structural check over the source: every C entry
// point must install the panic guard and clear each of its out-parameters before
// doing any work. Asserting this once here means a newly-added export cannot
// silently reintroduce either hazard -- the alternative is a hand-written probe
// per entry point, which is exactly the coverage that tends not to get added.
func TestEveryExportIsGuarded(t *testing.T) {
	// Entry points that cannot fail and have no out-parameters: lotman_version
	// returns a static string, and the list-free function returns void, so
	// neither can carry a `rc`/err_msg pair.
	exempt := map[string]bool{"lotman_version": true, "lotman_free_string_list": true}

	files, err := filepath.Glob("export*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("globbing export files: %v (found %d)", err, len(files))
	}

	checked := 0
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		fset := token.NewFileSet()
		// Parse with comments so the //export directives are visible.
		f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil || fn.Body == nil {
				continue
			}
			isExport := false
			for _, c := range fn.Doc.List {
				if strings.HasPrefix(c.Text, "//export ") {
					isExport = true
				}
			}
			if !isExport || exempt[fn.Name.Name] {
				continue
			}
			checked++
			body := nodeText(fset, src, fn.Body)

			// The return must be named so the guard can rewrite it.
			if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 || len(fn.Type.Results.List[0].Names) != 1 {
				t.Errorf("%s: expected a single named result (e.g. `(rc C.int)`) so guard can set it", fn.Name.Name)
				continue
			}
			rcName := fn.Type.Results.List[0].Names[0].Name
			wantGuard := "defer guard(errMsg, &" + rcName + ")"
			if !strings.Contains(body, wantGuard) {
				t.Errorf("%s: missing %q -- a panic here would abort the host process", fn.Name.Name, wantGuard)
			}

			// Every pointer-shaped out-parameter must be cleared on entry.
			for _, p := range fn.Type.Params.List {
				typ := nodeText(fset, src, p.Type)
				var want string
				switch typ {
				case "***C.char":
					want = "clearList"
				case "**C.char":
					want = "clearStr"
				case "*C.int":
					want = "clearInt"
				default:
					continue
				}
				for _, n := range p.Names {
					call := want + "(" + n.Name + ")"
					if !strings.Contains(body, call) {
						t.Errorf("%s: missing %q -- consumers free out-params without checking the return code", fn.Name.Name, call)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no //export functions to check; the glob or parse is wrong")
	}
	t.Logf("checked %d C entry points", checked)
}
