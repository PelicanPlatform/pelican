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
		// Levels declares which log levels this filter observes; Fire is only
		// invoked for entries at these levels. The declaration also feeds
		// logrusLevelFor, which raises logrus's internal level just far enough
		// for the filter to see what it asked for. Leaving Levels empty means
		// "observe everything" -- at the cost of pinning logrus to TraceLevel
		// (full entry construction for every suppressed log call in the
		// process) for as long as the filter is registered.
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

	// Guards the one-time formatter setup. SetLogging is reachable
	// concurrently -- the runtime log-level API calls it per request -- so
	// the "have we done this yet" flag cannot be a plain bool.
	formatterOnce sync.Once

	// effectiveLogLevel is the fast-path cache for GetEffectiveLogLevel.
	// shouldBuffer reads it on every incoming log line, so answering the
	// query must stay a single atomic load: it cannot take
	// globalTransformMu or walk the transform hook's LogLevels slice, which
	// is what the level would otherwise have to be derived from. It is the
	// authoritative record of the operator-configured level: seeded at
	// package init and written ONLY by SetLogging (called by the
	// param-callback registered via RegisterLoggingCallback). Every other
	// level-changing site derives from it; none may write it.
	effectiveLogLevel atomic.Uint32

	// testLogFloor is a level floor declared by a test harness whose log hook
	// forwards entries to t.Log for failure diagnostics (see
	// test_utils.SetupTestLogging). Zero means "no floor". It participates in
	// logrusLevelFor the same way the ring buffer and registered filters do,
	// which is what lets the harness's verbosity survive a mid-test
	// InitClient/InitServer re-deriving the level from the configured value.
	testLogFloor atomic.Uint32
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
	// Seed the effective-level cache with logrus's boot default (info)
	// so GetEffectiveLogLevel returns something sane between package
	// init and the first SetLogging call.
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
		// logrusLevelFor uses the same declaration to decide how far logrus's
		// level gate must open, so declaration and delivery stay in agreement.
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

	redactEntryInPlace(entry)
	return hook.Fire(entry)
}

// redactEntryInPlace censors credentials in an entry's message and "url"
// field. Mutating the caller's entry is what makes the censor effective for
// logrus's own output path: this hook owns the writer, so every consumer
// downstream of it sees the censored text.
//
// Any consumer that reads an entry WITHOUT going through this hook -- a hook
// registered ahead of this one, or one that formats the entry itself -- sees
// the raw credential and must call redactEntryCopy instead. Hook order is not
// a durable guarantee: SetLogging rebuilds the hook set and re-appends the
// global hooks last, so a hook installed earlier stays ahead of this one.
func redactEntryInPlace(entry *log.Entry) {
	regex := globalTransform.regex.Load()
	if regex == nil {
		return
	}
	entry.Message = regex.ReplaceAllString(entry.Message, globalTransform.template)
	for key, value := range entry.Data {
		if key != "url" {
			continue
		}
		if s, ok := value.(string); ok {
			entry.Data[key] = regex.ReplaceAllString(s, globalTransform.template)
		}
	}
}

// redactEntryCopy returns a censored copy of entry, leaving the caller's entry
// untouched so hooks that run later still observe what logrus handed them.
// The copy is shallow apart from Data, which is cloned only when it holds a
// field the censor rewrites.
//
// Callers that format an entry into storage a user can read back -- rather
// than into the writer redactEntryInPlace already covers -- must route it
// through here first.
func redactEntryCopy(entry *log.Entry) *log.Entry {
	regex := globalTransform.regex.Load()
	if regex == nil {
		return entry
	}
	template := globalTransform.template

	message := regex.ReplaceAllString(entry.Message, template)
	// Rewrite "url" only when the censor actually changes it, so the common
	// case (no credential in the entry) allocates nothing.
	var data log.Fields
	if raw, ok := entry.Data["url"].(string); ok {
		if censored := regex.ReplaceAllString(raw, template); censored != raw {
			data = make(log.Fields, len(entry.Data))
			for k, v := range entry.Data {
				data[k] = v
			}
			data["url"] = censored
		}
	}
	if message == entry.Message && data == nil {
		return entry
	}

	dup := *entry
	dup.Message = message
	if data != nil {
		dup.Data = data
	}
	// The formatter writes into Buffer when it is non-nil; that buffer belongs
	// to logrus's own write path and must not be shared with a copy.
	dup.Buffer = nil
	return &dup
}

// logrusLevelFor returns the level logrus itself should run at: the
// operator's configured level, raised only as far as the registered
// consumers of sub-level entries need to observe. Today those consumers are
// registered RegexpFilters (each declaring its Levels) and the log ring
// buffer (a standing info-and-above floor while installed). logrus's level gate sits in front of all
// entry construction (formatting, hook dispatch, and three acquisitions of
// the logger's global mutex), so keeping the level as low as possible is
// what spares suppressed Tracef/Debugf calls on hot request paths the
// formatting, hook dispatch, and global-mutex traffic of entry construction
// (argument boxing may still allocate at call sites with parameters).
//
// A filter that does not declare Levels is assumed to need everything,
// which restores the historical pin to TraceLevel while it is registered.
//
// If another filter needs to be added in lets move to a new method of level
// registration to enable rather than continuously piling on.
func logrusLevelFor(configured log.Level) log.Level {
	needed := floorLevelFor(configured)
	if filters := globalFilters.filters.Load(); filters != nil {
		for _, filter := range *filters {
			if len(filter.Levels) == 0 {
				return log.TraceLevel
			}
			for _, lvl := range filter.Levels {
				if lvl > needed {
					needed = lvl
				}
			}
		}
	}
	return needed
}

// floorLevelFor applies the standing level floors -- the consumers that must
// observe sub-configured entries in every logging mode, hook-based or not:
//
//   - The log ring buffer (served by the pelican.log_read triage endpoints)
//     documents that info and above are always captured, so a server running
//     a quiet Logging.Level still has recent context available for remote
//     triage. That contract must hold from the moment StartLogRingBuffer
//     runs -- which on a server is early in InitServer, well before
//     initFilterLogging installs hook-based output gating.
//   - A test harness forwarding entries to t.Log declares a floor so failing
//     tests keep their diagnostic output across in-test re-initialization.
//
// Unlike filter needs (see logrusLevelFor), floors deliberately apply even
// when hook-based filtering is inactive. In that mode logrus's Out is the
// real writer, so floor-admitted entries also reach the output -- e.g. a
// warn-configured server writes info lines during the InitServer window.
// That is the accepted price of the ring's "always captured" tier; once
// initFilterLogging installs the hook-gated writer, output returns to the
// configured level while the floors keep feeding the hooks.
func floorLevelFor(configured log.Level) log.Level {
	needed := configured
	if globalLogBuffer.Load() != nil && log.InfoLevel > needed {
		needed = log.InfoLevel
	}
	// testLogFloor == 0 means "no floor declared"; no explicit check is
	// needed because 0 is PanicLevel, the least verbose level, which can
	// never exceed `needed` -- the sentinel is inert by construction.
	if floor := log.Level(testLogFloor.Load()); floor > needed {
		needed = floor
	}
	return needed
}

// syncLogrusLevelLocked re-derives logrus's internal level after a change to
// the registered floors or filter set. Callers must hold globalTransformMu:
// SetLogging updates the level under the same mutex, so a derive-then-set
// outside it could interleave with a concurrent SetLogging and leave logrus
// below what a just-registered consumer needs (a lost update, and a consumer
// that never fires).
//
// Both branches derive from the effective-level cache -- the authoritative
// record of the operator's configured level (seeded at package init, stored
// unconditionally by SetLogging) -- never from log.GetLevel(), which may
// already be floor-raised; deriving from it would make the sync a one-way
// ratchet that can never lower the level after a floor is lifted. Filter
// needs apply only when hook-based filtering is active; otherwise raising
// the level for a filter would leak filter-only lines straight to the
// output. Floors (ring buffer, test harness) apply in both modes -- see
// floorLevelFor.
func syncLogrusLevelLocked() {
	if addedGlobalFilters {
		log.SetLevel(logrusLevelFor(GetEffectiveLogLevel()))
	} else {
		log.SetLevel(floorLevelFor(GetEffectiveLogLevel()))
	}
}

func initFilterLogging() {

	// The mutex serializes the read-modify-write on the filter list against
	// concurrent Add/Remove calls, and the level update against SetLogging.
	globalTransformMu.Lock()
	defer globalTransformMu.Unlock()

	// Our filters may want to see log messages that are not otherwise
	// printed. Printing happens via a hook (instead of the typical output
	// mechanism), so logrus's own level only controls which entries the
	// hooks get to see -- raise it no further than the filters require.
	//
	// Only initialize the filter list on first use: re-entry happens at
	// runtime (config.InitClient is reachable inside a server process, e.g.
	// from the local-cache module) and must not unregister live filters
	// such as the xrootd startup watchers.
	if globalFilters.filters.Load() == nil {
		filters := make([]*RegexpFilter, 0)
		globalFilters.filters.Store(&filters)
	}

	// The effective-level cache is the authoritative record of what the
	// operator configured: SetLogging stores it unconditionally before any
	// init path reaches this function, and the package-init seed covers the
	// window before that. logrus's own log.GetLevel() is NOT a valid source
	// here on either pass -- it may already be raised above the configured
	// level by a standing floor (ring buffer, test harness) or a registered
	// filter, and caching a raised value would poison GetEffectiveLogLevel
	// for every consumer that gates behavior on it (debug headers, the ring
	// buffer's debug/trace tier, config printing).
	//
	// Historically the level was pinned to TraceLevel here so the filter
	// hooks could see every message. That forced every suppressed
	// Tracef/Debugf in the codebase to pay full logrus entry construction
	// (three global-mutex acquisitions and a formatting pass) on hot
	// request paths; now the level is raised only as far as registered
	// consumers actually need (see logrusLevelFor).
	configLevel := GetEffectiveLogLevel()
	log.SetLevel(logrusLevelFor(configLevel))
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
}

// SetTestLogFloor declares that a test harness needs logrus to admit entries
// at lvl and below-severity regardless of the configured level, so its log
// hook (which forwards entries to t.Log) keeps receiving diagnostics when a
// test re-initializes logging via InitClient/InitServer. Cleared with
// ClearTestLogFloor; intended only for test harnesses.
// The returned restore function reinstates the floor that was in effect
// before this call, so nested harnesses (a package-level
// SetupGlobalTestLogging plus per-test SetupTestLogging, or parent tests
// with subtests) do not wipe each other's declarations.
func SetTestLogFloor(lvl log.Level) (restore func()) {
	prev := testLogFloor.Swap(uint32(lvl))
	globalTransformMu.Lock()
	syncLogrusLevelLocked()
	globalTransformMu.Unlock()
	return func() {
		testLogFloor.Store(prev)
		globalTransformMu.Lock()
		syncLogrusLevelLocked()
		globalTransformMu.Unlock()
	}
}

// ClearTestLogFloor removes the floor installed by SetTestLogFloor.
func ClearTestLogFloor() {
	testLogFloor.Store(0)
	globalTransformMu.Lock()
	defer globalTransformMu.Unlock()
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
	// Deliberately leave effectiveLogLevel alone: it is the authoritative
	// record of what the operator configured (seeded at package init, then
	// stored by every SetLogging call), and writing a sentinel here would be
	// read back by the next initFilterLogging as "what the operator asked
	// for". A test that needs a specific level must establish it via
	// SetLogging; a harness that needs verbosity declares a floor via
	// SetTestLogFloor.
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
	// The new filter may need to observe levels below the configured one;
	// raise logrus's level accordingly for as long as it is registered.
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
	syncLogrusLevelLocked()
}

func SetLogging(logLevel log.Level) {
	// Update the fast-path cache first so any log-buffer Fire that fires
	// mid-reconfiguration reads at worst a slightly-early-but-still-valid
	// value rather than a stale one from before this call.
	effectiveLogLevel.Store(uint32(logLevel))

	// Only configure the formatter once to preserve formatting across log level changes
	formatterOnce.Do(func() {
		textFormatter := log.TextFormatter{}
		textFormatter.DisableLevelTruncation = true
		textFormatter.FullTimestamp = true
		// Since we redirect log.Out to io.Discard, logrus will treat the output as non-terminal
		// and won't format logs with color. Here we bypass logrus check by forcing the color
		// and provide our check. Note that when calling SetLogging, io.Out hasn't been changed yet.
		textFormatter.ForceColors = term.IsTerminal(log.StandardLogger().Out)
		log.SetFormatter(&textFormatter)
	})

	// When global filters are active, we use hook-based filtering instead of logrus's
	// internal level filtering: the hooks decide what is written via hookLevel. logrus's
	// own level then only controls which entries reach the hooks, so run it at the
	// configured level, raised just far enough for any registered RegexpFilter to see
	// the messages it declared interest in (see logrusLevelFor).
	globalTransformMu.Lock()
	if addedGlobalFilters {
		log.SetLevel(logrusLevelFor(logLevel))
		hookLevel := make([]log.Level, 0, len(log.AllLevels))

		// Atomically get current hooks
		emptyHooks := log.LevelHooks{}
		currentHooks := log.StandardLogger().ReplaceHooks(emptyHooks)
		// Reinstall a copy at once so the logger is never hookless while we
		// rebuild: with Out at io.Discard, entries emitted in that window
		// would be lost entirely. The copy matters because currentHooks is
		// read below while logrus writes to the reinstalled set. Same
		// pattern as removeLogRingBufferHook.
		log.StandardLogger().ReplaceHooks(copyLevelHooks(currentHooks))

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
		// Install the rebuilt set before releasing the mutex: Start/Stop of
		// the ring buffer mutate the same hook set under this mutex, so
		// swapping after unlock could overwrite a concurrent install with
		// our stale snapshot (an installed-but-starved ring buffer).
		log.StandardLogger().ReplaceHooks(newHooks)
		globalTransformMu.Unlock()
	} else {
		// No hook-based gating yet: logrus's own level is the output gate.
		// Still honor the standing floors (ring buffer, test harness) so
		// their capture contracts hold before initFilterLogging runs; see
		// floorLevelFor for the output-leak trade this accepts.
		log.SetLevel(floorLevelFor(logLevel))
		globalTransformMu.Unlock()
	}
}

// GetEffectiveLogLevel returns the effective log level -- the level the
// operator asked for, as opposed to logrus's internal log.GetLevel(),
// which may sit temporarily above it while a registered RegexpFilter needs
// to observe more verbose entries (see logrusLevelFor). The value is
// served from an atomic cache seeded at package init and updated only by
// SetLogging; the hot path (LogRingBuffer.shouldBuffer, invoked on every
// entry) is therefore a single atomic load with no mutex contention or
// slice walk.
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
