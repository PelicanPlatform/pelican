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

package origin_serve

import (
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/param"
)

// The typed param setters below restore the previous value on cleanup so
// package-global config mutations don't leak into sibling tests. They use the
// typed .Set() (not viper.Set) because param getters read from a decoded
// config struct that viper.Set alone would not refresh.
//
// These live in an un-tagged file (compiled on every platform) because they
// are shared between tests that are excluded on Windows (the full-stack e2e
// suites) and tests that run everywhere (the admin auth suite).

func setStringParamForTest(t *testing.T, p param.StringParam, value string) {
	t.Helper()
	prev := p.GetString()
	if err := p.Set(value); err != nil {
		t.Fatalf("set %s: %v", p.GetName(), err)
	}
	t.Cleanup(func() { _ = p.Set(prev) })
}

func setBoolParamForTest(t *testing.T, p param.BoolParam, value bool) {
	t.Helper()
	prev := p.GetBool()
	if err := p.Set(value); err != nil {
		t.Fatalf("set %s: %v", p.GetName(), err)
	}
	t.Cleanup(func() { _ = p.Set(prev) })
}

func setDurationParamForTest(t *testing.T, p param.DurationParam, value time.Duration) {
	t.Helper()
	prev := p.GetDuration()
	if err := p.Set(value); err != nil {
		t.Fatalf("set %s: %v", p.GetName(), err)
	}
	t.Cleanup(func() { _ = p.Set(prev) })
}
