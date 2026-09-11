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
	"slices"
	"strconv"
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

	// effectiveLogLevel is the authoritative record of the operator-configured
	// level: seeded at package init and written only by SetLogging. It is what
	// GetEffectiveLogLevel returns, so consumers read the configured level from
	// one atomic load rather than inferring it from logrus's own level (which
	// the filter pipeline historically pinned to Trace). Every other
	// level-changing site derives from it; none may write it.
	effectiveLogLevel atomic.Uint32

	// levelDemands holds every consumer that needs logrus to admit entries
	// below the operator-configured level -- registered RegexpFilters and test
	// harnesses -- keyed by a stable string. It is guarded by globalTransformMu
	// and read by deriveLevelLocked. (A log ring buffer, when one is added,
	// registers its info floor here too.)
	levelDemands = map[string]levelDemand{}

	// demandSeq stamps each RegisterLevelDemand registration with a unique
	// sequence number (so a superseded registration's release is a no-op) and
	// hands each SetTestLogFloor call a unique demand key.
	demandSeq atomic.Uint64
)

// levelDemand is one consumer's declared need for logrus to admit entries at
// `level` or more verbose. A hookOnly demand counts only while hook-based
// filtering is active (see deriveLevelLocked). seq identifies the registration
// that installed it, so a release from a superseded RegisterLevelDemand call
// does not remove a newer demand under the same key (zero for demands set
// through the internal locked helpers, which release unconditionally by key).
type levelDemand struct {
	level    log.Level
	hookOnly bool
	seq      uint64
}

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
	// Seed the effective-level cache with logrus's boot default (info) so
	// GetEffectiveLogLevel returns something sane between package init and the
	// first SetLogging call.
	effectiveLogLevel.Store(uint32(log.GetLevel()))
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
		// A filter only observes the levels it declared (empty means all).
		// syncFilterDemandLocked uses the same declaration to decide how far
		// logrus's level gate must open, so declaration and delivery agree.
		if len(filter.Levels) > 0 && !slices.Contains(filter.Levels, entry.Level) {
			continue
		}
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
		for key, value := range entry.Data {
			if key != "url" {
				continue
			}
			if s, ok := value.(string); ok {
				entry.Data[key] = regex.ReplaceAllString(s, rt.template)
			}
		}
	}
	return hook.Fire(entry)
}

func initFilterLogging() {
	// The mutex serializes the read-modify-write on the filter list against
	// concurrent Add/Remove calls, and the level update against SetLogging.
	globalTransformMu.Lock()
	defer globalTransformMu.Unlock()

	// Our filters may want to see log messages that are not otherwise printed.
	// Printing happens via a hook (instead of the typical output mechanism), so
	// logrus's own level only controls which entries the hooks get to see --
	// raise it no further than the filters require.
	//
	// Only initialize the filter list on first use: re-entry happens at runtime
	// (config.InitClient is reachable inside a server process, e.g. from the
	// local-cache module) and must not unregister live filters such as the
	// xrootd startup watchers.
	if globalFilters.filters.Load() == nil {
		filters := make([]*RegexpFilter, 0)
		globalFilters.filters.Store(&filters)
	}

	// The effective-level cache is the authoritative record of what the
	// operator configured; historically the level was pinned to TraceLevel here
	// so the filter hooks could see every message, which forced every suppressed
	// Tracef/Debugf in the codebase to pay full logrus entry construction on hot
	// request paths. Now the level is raised only as far as registered consumers
	// actually need (see deriveLevelLocked).
	configLevel := GetEffectiveLogLevel()
	hookLevel := make([]log.Level, 0)
	for _, lvl := range log.AllLevels {
		if lvl <= configLevel {
			hookLevel = append(hookLevel, lvl)
		}
	}

	// Unit tests may initialize the server multiple times; avoid configuring
	// the global logging multiple times
	if !addedGlobalFilters {
		addedGlobalFilters = true
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
	}

	// Re-derive now that addedGlobalFilters is set: the hookOnly filter demands
	// apply from here on, so the gate opens to what the filters need.
	syncLogrusLevelLocked()
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

// deriveLevelLocked returns the level logrus must run at: the operator's
// configured level, raised to satisfy every registered demand that applies in
// the current gating mode.
//
// The configured level comes from the effective-level cache, never from
// log.GetLevel(): log.GetLevel() may already be raised by a standing demand,
// so deriving from it would make the derivation a one-way ratchet that could
// never lower the level once a demand is released.
//
// A hookOnly demand -- a RegexpFilter -- counts only while hook-based filtering
// is active: in that mode logrus's level merely decides which entries reach the
// hooks, so opening the gate for a filter costs nothing on the output. Before
// hook-based filtering is installed logrus's Out is the real writer, so raising
// the gate for a filter would leak filter-only lines to the output; those
// demands are skipped until then. Floors (e.g. a test harness) are not hookOnly
// and apply in both modes.
//
// Callers must hold globalTransformMu.
func deriveLevelLocked() log.Level {
	needed := GetEffectiveLogLevel()
	for _, d := range levelDemands {
		if d.hookOnly && !addedGlobalFilters {
			continue
		}
		needed = max(needed, d.level)
	}
	return needed
}

// syncLogrusLevelLocked re-derives and applies logrus's internal level after a
// change to the registered demands, the filter set, or the configured level.
// Callers must hold globalTransformMu: SetLogging updates the level under the
// same mutex, so a derive-then-set outside it could interleave with a
// concurrent SetLogging and leave logrus below what a just-registered consumer
// needs (a lost update, and a consumer that never fires).
func syncLogrusLevelLocked() {
	log.SetLevel(deriveLevelLocked())
}

// registerLevelDemandLocked records a demand and releaseLevelDemandLocked
// removes it. Both only mutate the map; the caller re-derives the level (it
// already holds the mutex and usually batches the demand change with other
// work). Callers must hold globalTransformMu.
func registerLevelDemandLocked(key string, level log.Level, hookOnly bool) {
	levelDemands[key] = levelDemand{level: level, hookOnly: hookOnly}
}

func releaseLevelDemandLocked(key string) {
	delete(levelDemands, key)
}

// RegisterLevelDemand declares that the consumer identified by `key` needs
// logrus to admit entries at `level` or more verbose, regardless of the
// operator-configured level, and returns a function that withdraws the demand.
// The gate is raised immediately and re-derived when the demand is withdrawn.
// Re-registering the same key replaces its level; the release returned by the
// superseded call then becomes a no-op, so independent owners sharing a key
// never withdraw one another's live demand.
//
// This is the general mechanism behind filter needs and the test-harness floor
// (SetTestLogFloor), and is where a log ring buffer would register its info
// floor: a new consumer that must observe sub-configured entries should
// register here rather than growing another special case. Demands registered
// through this exported entry point are floors -- they hold in every logging
// mode. (Filter needs, which apply only in hook mode, are registered
// internally.)
func RegisterLevelDemand(key string, level log.Level) (release func()) {
	seq := demandSeq.Add(1)
	globalTransformMu.Lock()
	levelDemands[key] = levelDemand{level: level, hookOnly: false, seq: seq}
	syncLogrusLevelLocked()
	globalTransformMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			globalTransformMu.Lock()
			// Only remove the demand if this registration still owns the key:
			// a later RegisterLevelDemand(key, ...) supersedes us, and its demand
			// must survive our release.
			if d, ok := levelDemands[key]; ok && d.seq == seq {
				releaseLevelDemandLocked(key)
				syncLogrusLevelLocked()
			}
			globalTransformMu.Unlock()
		})
	}
}

// syncFilterDemandLocked recomputes the single "filters" demand from the live
// filter list: the max level any registered filter declared, or TraceLevel if
// any filter declares no Levels (it observes everything). Keying all filters
// under one demand -- rather than one demand per filter name -- matches a
// whole-list scan and avoids a same-name registration clobbering another
// filter's need. Caller must hold globalTransformMu.
func syncFilterDemandLocked() {
	filters := globalFilters.filters.Load()
	if filters == nil || len(*filters) == 0 {
		releaseLevelDemandLocked("filters")
		return
	}
	needed := log.PanicLevel
	for _, f := range *filters {
		if len(f.Levels) == 0 {
			needed = log.TraceLevel
			break
		}
		for _, lvl := range f.Levels {
			needed = max(needed, lvl)
		}
	}
	registerLevelDemandLocked("filters", needed, true)
}

// SetTestLogFloor declares that a test harness needs logrus to admit entries at
// lvl or more verbose regardless of the configured level, so its log hook
// (which forwards entries to t.Log) keeps receiving diagnostics when a test
// re-initializes logging via InitClient/InitServer. It returns a restore
// function that withdraws just this declaration. Each call takes a unique
// demand key, so concurrent or nested harnesses never wipe one another's floor
// and restores may run in any order. Intended only for test harnesses; it is a
// thin wrapper over RegisterLevelDemand.
func SetTestLogFloor(lvl log.Level) (restore func()) {
	key := "test-harness:" + strconv.FormatUint(demandSeq.Add(1), 10)
	return RegisterLevelDemand(key, lvl)
}

func AddFilter(newFilter *RegexpFilter) {
	// The mutex serializes the read-modify-write on the filter list against
	// concurrent Add/Remove calls, and the level update against SetLogging.
	globalTransformMu.Lock()
	defer globalTransformMu.Unlock()
	var existing []*RegexpFilter
	if filters := globalFilters.filters.Load(); filters != nil {
		existing = *filters
	}
	// Copy rather than append in place: Fire iterates the published slice
	// lock-free, so a published slice must never be mutated afterward.
	newFilters := make([]*RegexpFilter, 0, len(existing)+1)
	newFilters = append(newFilters, existing...)
	newFilters = append(newFilters, newFilter)
	globalFilters.filters.Store(&newFilters)
	// Recompute the filters' collective demand so logrus's level is raised for
	// as long as a filter needs sub-configured entries (a hookOnly demand).
	syncFilterDemandLocked()
	syncLogrusLevelLocked()
}

func RemoveFilter(name string) {
	globalTransformMu.Lock()
	defer globalTransformMu.Unlock()
	var existing []*RegexpFilter
	if filters := globalFilters.filters.Load(); filters != nil {
		existing = *filters
	}
	result := make([]*RegexpFilter, 0, len(existing))
	for _, filter := range existing {
		if filter.Name != name {
			result = append(result, filter)
		}
	}
	globalFilters.filters.Store(&result)
	// Drop logrus's level back down if this filter was what held it up.
	syncFilterDemandLocked()
	syncLogrusLevelLocked()
}

func SetLogging(logLevel log.Level) {
	// Record the operator-configured level first so any concurrent reader of
	// GetEffectiveLogLevel sees at worst a slightly-early-but-valid value.
	effectiveLogLevel.Store(uint32(logLevel))

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

	// When global filters are active, hook-based filtering decides what is
	// written (via hookLevel); logrus's own level only controls which entries
	// reach the hooks, so run it at the configured level raised only as far as
	// any registered consumer needs (see deriveLevelLocked).
	globalTransformMu.Lock()
	if addedGlobalFilters {
		syncLogrusLevelLocked()
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

		// Add globalFilters at ALL levels so it can see every message for regex-based filtering
		for _, lvl := range log.AllLevels {
			newHooks[lvl] = append(newHooks[lvl], &globalFilters)
		}
		// Add globalTransform only at hookLevel — writer.Hook.Fire() writes unconditionally,
		// so registering at all levels would leak trace/debug messages to the output.
		for _, lvl := range hookLevel {
			newHooks[lvl] = append(newHooks[lvl], globalTransform)
		}
		globalTransformMu.Unlock()

		// Atomically replace all hooks
		log.StandardLogger().ReplaceHooks(newHooks)
	} else {
		// No hook-based gating yet: logrus's own level is the output gate. Still
		// honor any standing floors (e.g. a test harness) via the derivation.
		syncLogrusLevelLocked()
		globalTransformMu.Unlock()
	}
}

// GetEffectiveLogLevel returns the effective log level -- the level the
// operator asked for, as opposed to logrus's internal log.GetLevel(), which
// the filter pipeline historically pinned to Trace so filters could observe
// every message. The value is served from an atomic cache seeded at package
// init and updated only by SetLogging, so answering the query is a single
// atomic load with no mutex contention.
func GetEffectiveLogLevel() log.Level {
	return log.Level(effectiveLogLevel.Load())
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
