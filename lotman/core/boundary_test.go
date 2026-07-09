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

package core

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestNoPelicanImports enforces the standalone-module dependency boundary:
// the core package's non-test source must not import any Pelican package, so
// that core can be promoted to its own repository. Test files are exempt (they
// legitimately import a sqlite driver to open a database).
func TestNoPelicanImports(t *testing.T) {
	const forbidden = "github.com/pelicanplatform/pelican"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read core dir: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", name, err)
			}
			if strings.HasPrefix(path, forbidden) {
				t.Errorf("%s imports forbidden Pelican package %q; core must stay standalone", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no core source files were scanned; boundary check is ineffective")
	}
}
