/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"io"
	"os"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/go-kit/log/term"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"

	"github.com/pelicanplatform/pelican/param"
)

type (
	// syncWriter wraps an io.Writer to make writes thread-safe
	syncWriter struct {
		mu     sync.Mutex
		writer io.Writer
	}

	RegexpFilter struct {
		Regexp *regexp.Regexp
		Name   string
		Levels []log.Level
		Fire   func(*log.Entry) error
	}

	// A logrus hook that carries a list of regexp-based "filters".
	// If any of the filters matches the incoming log line, the corresponding
	// callback is invoked.
	RegexpFilterHook struct {
		filters atomic.Pointer[[]*RegexpFilter]
	}

	// A logrus hook that censors the contents of the logs.
	// If any of the log messages matches one of the regexps, then the corresponding
	// expansions are made.
	//
	// Intended to be used to censor or transform logs
	regexpTransformHook struct {
		hook     atomic.Pointer[writer.Hook]
		regex    atomic.Pointer[regexp.Regexp]
		template string
	}
)

var (
	globalFilters      RegexpFilterHook
	addedGlobalFilters bool
	globalTransformMu  sync.Mutex // Protects globalTransform, addedGlobalFilters, and related setup/teardown

	bearerTokenRegexStr string = `(?P<prefix>Bearer%20)?(?P<header>ey[A-Za-z0-9_=-]{18,})[.](?P<payload>ey[A-Za-z0-9_=-]{18,})[.]([A-Za-z0-9_=-]{64,})`

	globalTransform *regexpTransformHook

	// Track whether we've already configured the formatter to avoid resetting it
	formatterConfigured bool
)

func (sw *syncWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.writer.Write(p)
}

// ensureThreadSafeWriter wraps writers that are not inherently thread-safe (like bytes.Buffer)
// with a syncWriter to protect concurrent access. Files and os.Stderr/os.Stdout are thread-safe
// and don't need wrapping.
func ensureThreadSafeWriter(w io.Writer) io.Writer {
	// Check if already wrapped
	if _, ok := w.(*syncWriter); ok {
		return w
	}

	// Files (including os.Stderr, os.Stdout) are thread-safe
	if _, ok := w.(*os.File); ok {
		return w
	}

	// io.Discard is thread-safe
	if w == io.Discard {
		return w
	}

	// For bytes.Buffer and other potentially unsafe writers, wrap them
	if _, ok := w.(*bytes.Buffer); ok {
		return &syncWriter{writer: w}
	}

	// Default: assume unsafe and wrap
	return &syncWriter{writer: w}
}

func init() {
	globalTransform = &regexpTransformHook{
		template: "$prefix$header.$payload.REDACTED",
	}
	initialHook := &writer.Hook{
		Writer:    os.Stderr,
		LogLevels: log.AllLevels,
	}
	globalTransform.hook.Store(initialHook)
	initialRegex := regexp.MustCompile(bearerTokenRegexStr)
	globalTransform.regex.Store(initialRegex)
}

func (fh *RegexpFilterHook) Levels() []log.Level {
	return log.AllLevels
}

func (rt *regexpTransformHook) Levels() []log.Level {
	hook := rt.hook.Load()
	if hook == nil {
		return log.AllLevels
	}
	return hook.LogLevels
}

// Process a single log entry coming from logrus; iterate through the
// internal list of regexp filters and invoke any callbacks for regexps
// that match the entry.Message.
func (fh *RegexpFilterHook) Fire(entry *log.Entry) (err error) {
	filters := fh.filters.Load()
	for _, filter := range *filters {
		if filter.Regexp.MatchString(entry.Message) {
			curErr := filter.Fire(entry)
			if curErr != nil && err == nil {
				err = curErr
			}
		}
	}
	return
}

// Process a single log entry, updating it as necessary
func (rt *regexpTransformHook) Fire(entry *log.Entry) (err error) {
	// Use atomic loads for lock-free access on hot path
	hook := rt.hook.Load()
	if hook == nil {
		return nil
	}

	// Skip if writer is io.Discard (test mode)
	if hook.Writer == io.Discard {
		return nil
	}

	regex := rt.regex.Load()
	if regex != nil {
		entry.Message = regex.ReplaceAllString(entry.Message, rt.template)
	}
	return hook.Fire(entry)
}

func initFilterLogging() {
	// Our filters may want to see every log message, even those that
	// are not otherwise printed.  Have the log levels printed via a hook
	// (instead of the typical output mechanism) so we can crank up the
	// global log.
	filters := make([]*RegexpFilter, 0)
	globalFilters.filters.Store(&filters)

	configLevel := log.GetLevel()
	log.SetLevel(log.TraceLevel)
	hookLevel := make([]log.Level, 0)
	for _, lvl := range log.AllLevels {
		if lvl <= configLevel {
			hookLevel = append(hookLevel, lvl)
		}
	}

	// Unit tests may initialize the server multiple times; avoid configuring
	// the global logging multiple times
	globalTransformMu.Lock()
	if !addedGlobalFilters {
		addedGlobalFilters = true
		globalTransformMu.Unlock()
		// Set the writer to what logrus has
		newHook := &writer.Hook{
			Writer:    ensureThreadSafeWriter(log.StandardLogger().Out),
			LogLevels: hookLevel,
		}
		globalTransform.hook.Store(newHook)
		log.AddHook(&globalFilters)
		log.SetOutput(io.Discard)
		log.AddHook(globalTransform)
	} else {
		// Reset the regular expression.  This is done to reduce jitter in the memory
		// stress test; as this is called for each unit test run, this reduces the chance
		// prior unit tests affect this one.
		newRegex := regexp.MustCompile(bearerTokenRegexStr)
		globalTransform.regex.Store(newRegex)
		globalTransformMu.Unlock()
	}
}

// ResetGlobalLoggingHooks resets the global logging hooks and flags for testing.
// This should be called by test_utils.SetupTestLogging to ensure clean test state.
func ResetGlobalLoggingHooks() {
	globalTransformMu.Lock()
	defer globalTransformMu.Unlock()
	addedGlobalFilters = false
	if globalTransform != nil {
		newHook := &writer.Hook{
			Writer:    ensureThreadSafeWriter(io.Discard),
			LogLevels: log.AllLevels,
		}
		globalTransform.hook.Store(newHook)
	}
}

func AddFilter(newFilter *RegexpFilter) {
	filters := globalFilters.filters.Load()
	var newFilters []*RegexpFilter
	if filters == nil {
		newFilters = make([]*RegexpFilter, 0)
	} else {
		newFilters = *filters
	}
	newFilters = append(newFilters, newFilter)
	globalFilters.filters.Store(&newFilters)
}

func RemoveFilter(name string) {
	filters := *globalFilters.filters.Load()
	result := make([]*RegexpFilter, 0)
	for _, filter := range filters {
		if filter.Name != name {
			result = append(result, filter)
		}
	}
	globalFilters.filters.Store(&result)
}

func SetLogging(logLevel log.Level) {
	// Only configure the formatter once to preserve formatting across log level changes
	if !formatterConfigured {
		textFormatter := log.TextFormatter{}
		textFormatter.DisableLevelTruncation = true
		textFormatter.FullTimestamp = true
		// Since we redirect log.Out to io.Discard, logrus will treat the output as non-terminal
		// and won't format logs with color. Here we bypass logrus check by forcing the color
		// and provide our check. Note that when calling SetLogging, io.Out hasn't been changed yet.
		textFormatter.ForceColors = term.IsTerminal(log.StandardLogger().Out)
		log.SetFormatter(&textFormatter)
		formatterConfigured = true
	}

	// When global filters are active, we use hook-based filtering instead of logrus's
	// internal level filtering. We set logrus to TraceLevel (the most permissive) so
	// that ALL log messages pass through to our hooks; the hooks then filter based on
	// the user's configured level via hookLevel. This approach allows our RegexpFilterHook
	// to see all messages regardless of the configured output level.
	globalTransformMu.Lock()
	if addedGlobalFilters {
		log.SetLevel(log.TraceLevel)
		hookLevel := make([]log.Level, 0, len(log.AllLevels))

		// Atomically get current hooks
		emptyHooks := log.LevelHooks{}
		currentHooks := log.StandardLogger().ReplaceHooks(emptyHooks)

		// Build new hooks map, removing our global hooks
		newHooks := log.LevelHooks{}
		for _, lvl := range log.AllLevels {
			originalHooks := currentHooks[lvl]
			newHooks[lvl] = make([]log.Hook, 0, len(originalHooks))
			for _, hook := range originalHooks {
				if hook != &globalFilters && hook != globalTransform {
					newHooks[lvl] = append(newHooks[lvl], hook)
				}
			}
			if lvl <= logLevel {
				hookLevel = append(hookLevel, lvl)
			}
		}

		// Update hook with new log levels
		currentHook := globalTransform.hook.Load()
		newHook := &writer.Hook{
			Writer:    ensureThreadSafeWriter(currentHook.Writer),
			LogLevels: hookLevel,
		}
		globalTransform.hook.Store(newHook)

		// Add our hooks back
		for _, lvl := range log.AllLevels {
			newHooks[lvl] = append(newHooks[lvl], &globalFilters)
			newHooks[lvl] = append(newHooks[lvl], globalTransform)
		}
		globalTransformMu.Unlock()

		// Atomically replace all hooks
		log.StandardLogger().ReplaceHooks(newHooks)
	} else {
		globalTransformMu.Unlock()
		log.SetLevel(logLevel)
	}
}

// GetEffectiveLogLevel returns the effective log level based on the transform hook.
// When global filters are active, logrus's log.GetLevel() is set to TraceLevel to allow
// filters to see all messages, while the actual filtering happens via hooks. This function
// returns the true effective level by examining what levels the hook is configured to output.
func GetEffectiveLogLevel() log.Level {
	globalTransformMu.Lock()
	defer globalTransformMu.Unlock()
	if addedGlobalFilters && globalTransform != nil {
		hook := globalTransform.hook.Load()
		if hook == nil {
			return log.GetLevel()
		}
		// Find the highest (most verbose) level in the hook's configured levels.
		// In logrus, higher numeric values = more verbose (Trace=6 > Debug=5 > ... > Panic=0).
		// The hook's LogLevels contains all levels that should be output, so the max
		// value represents the effective log level.
		var maxLevel log.Level
		for _, hookLvl := range hook.LogLevels {
			if hookLvl > maxLevel {
				maxLevel = hookLvl
			}
		}
		return maxLevel
	}
	return log.GetLevel()
}

// Disable the logging censor functionality
//
// Provided so we can disable the censoring in unit tests;
// otherwise, it should not be used
func DisableLoggingCensor() {
	globalTransform.regex.Store(nil)
}

// RegisterLoggingCallback registers a callback with the param module
// to update logging configuration when Logging.Level changes.
func RegisterLoggingCallback() {
	param.RegisterCallback("logging", func(oldConfig, newConfig *param.Config) {
		if oldConfig == nil || newConfig == nil {
			return
		}

		oldLevel, oldErr := log.ParseLevel(oldConfig.Logging.Level)
		newLevel, newErr := log.ParseLevel(newConfig.Logging.Level)
		if newErr != nil {
			log.Errorf("Failed to parse new log level %q: %v", newConfig.Logging.Level, newErr)
			return
		}
		// Apply changes whenever the parsed level differs (case-insensitive) or old level failed to parse.
		if oldErr != nil || oldLevel != newLevel {
			log.Infof("Updating log level from %s to %s", oldConfig.Logging.Level, newConfig.Logging.Level)
			SetLogging(newLevel)
		}
	})
}
