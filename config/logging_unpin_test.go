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

package config

import (
	"io"
	"regexp"
	"sync/atomic"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// countingFormatter counts how many entries reach logrus's formatting stage.
// A suppressed log line must never get this far.
type countingFormatter struct{ count atomic.Int64 }

func (c *countingFormatter) Format(e *log.Entry) ([]byte, error) {
	c.count.Add(1)
	return []byte{}, nil
}

// The hook-based filter pipeline must not pin logrus's internal level to Trace:
// a Tracef/Debugf below the configured level has to be rejected by the level
// gate before any entry is constructed, or hot request paths pay formatting
// plus global-mutex acquisitions per suppressed line.
func TestLogrusLevelNotPinnedByFilterInit(t *testing.T) {
	prevLevel := log.GetLevel()
	prevEffective := GetEffectiveLogLevel()
	prevOut := log.StandardLogger().Out
	prevFormatter := log.StandardLogger().Formatter
	prevHooks := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	t.Cleanup(func() {
		log.StandardLogger().ReplaceHooks(prevHooks)
		log.SetFormatter(prevFormatter)
		log.SetOutput(prevOut)
		SetLogging(prevEffective)
		log.SetLevel(prevLevel)
		ResetGlobalLoggingHooks()
	})

	ResetGlobalLoggingHooks()
	log.SetOutput(io.Discard)
	SetLogging(log.InfoLevel)
	initFilterLogging()

	assert.Equal(t, log.InfoLevel, log.GetLevel(),
		"initFilterLogging must not raise logrus above the configured level when no filters are registered")

	cf := &countingFormatter{}
	log.SetFormatter(cf)
	log.Tracef("suppressed %d", 42)
	log.Debugf("suppressed %d", 43)
	assert.Zero(t, cf.count.Load(),
		"suppressed lines must not construct entries or run the formatter")
	log.Infof("emitted %d", 44)
	assert.Positive(t, cf.count.Load(), "lines at the configured level must still be emitted")

	// A filter declaring interest in Debug raises the level while registered...
	noop := func(*log.Entry) error { return nil }
	AddFilter(&RegexpFilter{Name: "test_debug", Regexp: regexp.MustCompile("x"),
		Levels: []log.Level{log.DebugLevel}, Fire: noop})
	assert.Equal(t, log.DebugLevel, log.GetLevel(),
		"a registered filter must raise logrus's level to what it needs to observe")

	// ...and the level drops back once it is gone.
	RemoveFilter("test_debug")
	assert.Equal(t, log.InfoLevel, log.GetLevel(),
		"removing the filter must restore the configured level")

	// A filter that declares no levels is assumed to need everything.
	AddFilter(&RegexpFilter{Name: "test_all", Regexp: regexp.MustCompile("x"), Fire: noop})
	assert.Equal(t, log.TraceLevel, log.GetLevel())
	RemoveFilter("test_all")
	assert.Equal(t, log.InfoLevel, log.GetLevel())

	// The operator-facing case that matters in production: Logging.Level set
	// quieter than Info while the xrootd startup filters (Levels: [Info]) are
	// registered. The gate must open to Info or startup detection hangs.
	SetLogging(log.WarnLevel)
	assert.Equal(t, log.WarnLevel, log.GetLevel())
	AddFilter(&RegexpFilter{Name: "test_startup", Regexp: regexp.MustCompile("x"),
		Levels: []log.Level{log.InfoLevel}, Fire: noop})
	assert.Equal(t, log.InfoLevel, log.GetLevel(),
		"an Info-needing filter must raise logrus above a Warn-configured level")
	RemoveFilter("test_startup")
	assert.Equal(t, log.WarnLevel, log.GetLevel())

	SetLogging(log.ErrorLevel)
	assert.Equal(t, log.ErrorLevel, log.GetLevel())
}

// Without hook-based filtering active, filter registration must not touch
// logrus's level: in that mode logrus's own level IS the output gate, and
// raising it would leak filter-only lines straight to the output.
func TestFilterRegistrationNoopWithoutHooks(t *testing.T) {
	prevLevel := log.GetLevel()
	prevEffective := GetEffectiveLogLevel()
	t.Cleanup(func() {
		SetLogging(prevEffective)
		log.SetLevel(prevLevel)
		ResetGlobalLoggingHooks()
	})

	ResetGlobalLoggingHooks() // addedGlobalFilters = false
	SetLogging(log.WarnLevel)

	AddFilter(&RegexpFilter{Name: "test_noop", Regexp: regexp.MustCompile("x"),
		Levels: []log.Level{log.TraceLevel}, Fire: func(*log.Entry) error { return nil }})
	defer RemoveFilter("test_noop")

	assert.Equal(t, log.WarnLevel, log.GetLevel(),
		"filter registration must not raise logrus's level when hook-based filtering is inactive")
}

// Lifting a test-harness floor must lower logrus back to the configured level
// even before hook-based filtering is active. Regression test for the
// raise-only derivation bug: the non-hook sync must derive from the configured
// level, not from logrus's already-raised level.
func TestFloorLiftsInNonHookMode(t *testing.T) {
	prevLevel := log.GetLevel()
	prevEffective := GetEffectiveLogLevel()
	prevOut := log.StandardLogger().Out
	prevHooks := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	t.Cleanup(func() {
		log.StandardLogger().ReplaceHooks(prevHooks)
		log.SetOutput(prevOut)
		SetLogging(prevEffective)
		log.SetLevel(prevLevel)
		ResetGlobalLoggingHooks()
	})

	ResetGlobalLoggingHooks() // addedGlobalFilters = false for the whole test
	log.SetOutput(io.Discard)
	SetLogging(log.WarnLevel)

	restore := SetTestLogFloor(log.TraceLevel)
	assert.Equal(t, log.TraceLevel, log.GetLevel())
	restore()
	assert.Equal(t, log.WarnLevel, log.GetLevel(),
		"restoring the test floor must lower logrus back to the configured level in non-hook mode")
}

// A test harness forwarding entries to t.Log declares a floor so that a test
// calling InitClient/InitServer mid-test (which re-derives the level from the
// configured value) does not silently starve its own failure diagnostics.
func TestHarnessLogFloorSurvivesReinit(t *testing.T) {
	prevLevel := log.GetLevel()
	prevEffective := GetEffectiveLogLevel()
	prevOut := log.StandardLogger().Out
	prevHooks := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	var restore func()
	t.Cleanup(func() {
		if restore != nil {
			restore()
		}
		log.StandardLogger().ReplaceHooks(prevHooks)
		log.SetOutput(prevOut)
		SetLogging(prevEffective)
		log.SetLevel(prevLevel)
		ResetGlobalLoggingHooks()
	})

	ResetGlobalLoggingHooks()
	log.SetOutput(io.Discard)
	restore = SetTestLogFloor(log.TraceLevel)

	// Simulate a mid-test InitClient/InitServer: init runs with a quiet
	// configured level, but the harness floor must keep the gate open.
	SetLogging(log.ErrorLevel)
	initFilterLogging()
	assert.Equal(t, log.TraceLevel, log.GetLevel(),
		"the harness floor must survive initFilterLogging")

	SetLogging(log.WarnLevel)
	assert.Equal(t, log.TraceLevel, log.GetLevel(),
		"the harness floor must survive SetLogging")

	restore()
	assert.Equal(t, log.WarnLevel, log.GetLevel(),
		"withdrawing the floor must restore the configured level")
}

// Test-harness floors are independent keyed demands, so nested or concurrent
// harnesses never wipe one another and their restores may run in any order --
// the gate always reflects the most verbose demand still outstanding.
func TestTestLogFloorNesting(t *testing.T) {
	prevLevel := log.GetLevel()
	prevEffective := GetEffectiveLogLevel()
	prevOut := log.StandardLogger().Out
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		SetLogging(prevEffective)
		log.SetLevel(prevLevel)
		ResetGlobalLoggingHooks()
	})

	ResetGlobalLoggingHooks()
	log.SetOutput(io.Discard)
	SetLogging(log.WarnLevel)

	outerRestore := SetTestLogFloor(log.InfoLevel)
	innerRestore := SetTestLogFloor(log.TraceLevel)
	assert.Equal(t, log.TraceLevel, log.GetLevel(),
		"the most verbose outstanding floor wins")

	// Restore out of nesting order -- the outer (less verbose) first.
	outerRestore()
	assert.Equal(t, log.TraceLevel, log.GetLevel(),
		"withdrawing a less-verbose floor leaves the more-verbose one intact")

	innerRestore()
	assert.Equal(t, log.WarnLevel, log.GetLevel(),
		"with no floors outstanding the gate returns to the configured level")
}

// A filter's Levels declaration must control which entries its Fire callback
// observes, so declaration and delivery agree (syncFilterDemandLocked uses the
// same declaration to decide how far the level gate opens).
func TestRegexpFilterLevelEnforcement(t *testing.T) {
	var declaredFired, undeclaredFired atomic.Int64

	hook := RegexpFilterHook{}
	filters := []*RegexpFilter{
		{Name: "declared", Regexp: regexp.MustCompile("match-me"),
			Levels: []log.Level{log.InfoLevel},
			Fire:   func(*log.Entry) error { declaredFired.Add(1); return nil }},
		{Name: "undeclared", Regexp: regexp.MustCompile("match-me"),
			Fire: func(*log.Entry) error { undeclaredFired.Add(1); return nil }},
	}
	hook.filters.Store(&filters)

	fire := func(lvl log.Level) {
		entry := &log.Entry{Logger: log.StandardLogger(), Level: lvl, Message: "match-me"}
		assert.NoError(t, hook.Fire(entry))
	}

	fire(log.InfoLevel)
	assert.Equal(t, int64(1), declaredFired.Load(), "declared level must be delivered")
	assert.Equal(t, int64(1), undeclaredFired.Load(), "empty Levels must observe everything")

	fire(log.DebugLevel)
	assert.Equal(t, int64(1), declaredFired.Load(), "undeclared level must not be delivered")
	assert.Equal(t, int64(2), undeclaredFired.Load(), "empty Levels must observe everything")
}
