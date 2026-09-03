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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
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

// The hook-based filter pipeline must not pin logrus's internal level to
// Trace: a Tracef/Debugf below the configured level has to be rejected by
// the level gate before any entry is constructed, or hot request paths pay
// formatting plus three global-mutex acquisitions per suppressed line.
func TestLogrusLevelNotPinnedByFilterInit(t *testing.T) {
	prevLevel := log.GetLevel()
	prevOut := log.StandardLogger().Out
	prevFormatter := log.StandardLogger().Formatter
	prevHooks := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	t.Cleanup(func() {
		log.StandardLogger().ReplaceHooks(prevHooks)
		log.SetFormatter(prevFormatter)
		log.SetOutput(prevOut)
		log.SetLevel(prevLevel)
		ResetGlobalLoggingHooks()
	})

	ResetGlobalLoggingHooks()
	log.SetOutput(io.Discard)
	log.SetLevel(log.InfoLevel)
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

	// SetLogging keeps the derived level in sync with the configured one.
	SetLogging(log.ErrorLevel)
	assert.Equal(t, log.ErrorLevel, log.GetLevel())
}

// Without hook-based filtering active, filter registration must not touch
// logrus's level: in that mode logrus's own level IS the output gate, and
// raising it would leak filter-only lines straight to the output.
func TestFilterRegistrationNoopWithoutHooks(t *testing.T) {
	prevLevel := log.GetLevel()
	t.Cleanup(func() {
		log.SetLevel(prevLevel)
		ResetGlobalLoggingHooks()
	})

	ResetGlobalLoggingHooks() // addedGlobalFilters = false
	log.SetLevel(log.WarnLevel)

	AddFilter(&RegexpFilter{Name: "test_noop", Regexp: regexp.MustCompile("x"),
		Levels: []log.Level{log.TraceLevel}, Fire: func(*log.Entry) error { return nil }})
	defer RemoveFilter("test_noop")

	assert.Equal(t, log.WarnLevel, log.GetLevel(),
		"filter registration must not raise logrus's level when hook-based filtering is inactive")
}

// A filter's Levels declaration must control which entries its Fire callback
// observes, so declaration and delivery agree (logrusLevelFor uses the same
// declaration to decide how far the level gate opens).
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
