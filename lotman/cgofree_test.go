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

package lotman_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestServerStaysCgoFree guards the migration's core build property: the
// pelican / pelican-server binaries embed the native Go lot engine
// (lotman/core) directly and must NOT link the cgo C-ABI shared library
// (lotman/cshared) or re-introduce the old purego binding to libLotMan.so.
// Either would force CGO back on and break static linking.
//
// It inspects the command's transitive dependency graph rather than building,
// so it is fast and runs in the normal test suite.
func TestServerStaysCgoFree(t *testing.T) {
	const cmdPkg = "github.com/pelicanplatform/pelican/cmd"
	forbidden := []string{
		"github.com/pelicanplatform/pelican/lotman/cshared",
		"github.com/ebitengine/purego",
	}
	const wantEngine = "github.com/pelicanplatform/pelican/lotman/core"

	for _, tags := range []string{"server", "client server"} {
		out, err := exec.Command("go", "list", "-deps", "-tags", tags, cmdPkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps -tags %q %s failed: %v\n%s", tags, cmdPkg, err, out)
		}
		deps := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			deps[strings.TrimSpace(line)] = true
		}

		for _, f := range forbidden {
			if deps[f] {
				t.Errorf("pelican (tags %q) must stay CGO-free but depends on %q", tags, f)
			}
		}
		if !deps[wantEngine] {
			t.Errorf("pelican (tags %q) should embed the native lot engine %q", tags, wantEngine)
		}
	}
}
