/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package logging

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

type (
	// LogLevelChange represents a temporary change to a log level
	LogLevelChange struct {
		Level         log.Level
		EndTime       time.Time
		ChangeID      string // Unique identifier for this change
		ParameterName string // Parameter name like "Logging.Level" or "Logging.Origin.Xrootd"
	}

	// LogLevelManager manages temporary log level changes
	LogLevelManager struct {
		mu            sync.RWMutex
		activeChanges map[string]*LogLevelChange // key is ChangeID
		baseLevels    map[string]log.Level       // base level captured when first change is made
		ctx           context.Context
		cancel        context.CancelFunc
		egrp          *errgroup.Group
		updateCh      chan struct{}
	}
)

var (
	globalManager        *LogLevelManager
	globalManagerOnce    sync.Once
	defaultCheckInterval = 30 * time.Second
)

// ResetGlobalManager resets the global manager (for testing only)
func ResetGlobalManager() {
	if globalManager != nil {
		globalManager.Shutdown()
	}
	globalManager = nil
	globalManagerOnce = sync.Once{}
}

// InitLogLevelManager initializes the global log level manager with custom functions
// This is called by the config package to inject the proper functions without creating an import cycle
// If egrp is nil, a new errgroup will be created for the background goroutine
func InitLogLevelManager(ctx context.Context, egrp *errgroup.Group, setFunc func(log.Level), getFunc func() log.Level) {
	globalManagerOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithCancel(ctx)
		if egrp == nil {
			egrp, ctx = errgroup.WithContext(ctx)
		}

		globalManager = &LogLevelManager{
			activeChanges: make(map[string]*LogLevelChange),
			baseLevels:    make(map[string]log.Level),
			ctx:           ctx,
			cancel:        cancel,
			egrp:          egrp,
			updateCh:      make(chan struct{}, 1),
		}

		globalManager.applyChanges()
		egrp.Go(func() error {
			globalManager.manageLogLevels()
			return nil
		})
	})
}

// GetLogLevelManager returns the global log level manager instance
func GetLogLevelManager() *LogLevelManager {
	globalManagerOnce.Do(func() {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		egrp, ctx := errgroup.WithContext(ctx)
		globalManager = &LogLevelManager{
			activeChanges: make(map[string]*LogLevelChange),
			baseLevels:    make(map[string]log.Level),
			ctx:           ctx,
			cancel:        cancel,
			egrp:          egrp,
			updateCh:      make(chan struct{}, 1),
		}
		globalManager.applyChanges()
		egrp.Go(func() error {
			globalManager.manageLogLevels()
			return nil
		})
	})
	return globalManager
}

// isValidLoggingParameter checks if a parameter name is valid for log level changes
// isValidLoggingParameter checks if a parameter name exists in the param.Config structure
// using reflection to validate the actual field path
func isValidLoggingParameter(paramName string) bool {
	// Split the parameter name into parts (e.g., "Logging.Origin.Xrootd" -> ["Logging", "Origin", "Xrootd"])
	parts := strings.Split(paramName, ".")

	// Must start with "Logging" and have at least 2 parts
	if len(parts) < 2 || parts[0] != "Logging" {
		return false
	}

	// Second level must be one of the valid categories
	validSecondLevels := map[string]bool{
		"Level":  true,
		"Cache":  true,
		"Origin": true,
	}
	if !validSecondLevels[parts[1]] {
		return false
	}

	// Use reflection to check if the path exists in param.Config
	configType := reflect.TypeOf(param.Config{})

	// Start with the Config struct
	currentType := configType
	for i, part := range parts {
		// Find the field with this name (case-insensitive struct tag matching)
		field, found := findFieldByName(currentType, part)
		if !found {
			return false
		}

		// If this is not the last part, make sure it's a struct so we can continue
		if i < len(parts)-1 {
			fieldType := field.Type
			if fieldType.Kind() != reflect.Struct {
				return false
			}
			currentType = fieldType
		} else {
			// Last part should be a string field (the actual log level parameter)
			return field.Type.Kind() == reflect.String
		}
	}

	return true
}

// findFieldByName searches for a struct field by name, matching against both
// the field name and yaml/mapstructure tags (case-insensitive)
func findFieldByName(structType reflect.Type, name string) (reflect.StructField, bool) {
	nameLower := strings.ToLower(name)

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)

		// Check field name (case-insensitive)
		if strings.ToLower(field.Name) == nameLower {
			return field, true
		}

		// Check yaml tag
		if yamlTag := field.Tag.Get("yaml"); yamlTag != "" {
			if strings.ToLower(yamlTag) == nameLower {
				return field, true
			}
		}

		// Check mapstructure tag
		if mapTag := field.Tag.Get("mapstructure"); mapTag != "" {
			if strings.ToLower(mapTag) == nameLower {
				return field, true
			}
		}
	}

	return reflect.StructField{}, false
}

// HasParameter returns true if the parameter is valid for log level changes
func (m *LogLevelManager) HasParameter(paramName string) bool {
	return isValidLoggingParameter(paramName)
}

// AddChange adds a new temporary log level change
func (m *LogLevelManager) AddChange(changeID string, parameterName string, level log.Level, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !isValidLoggingParameter(parameterName) {
		return errors.Errorf("unknown parameter %q", parameterName)
	}

	// Capture base level on first change for this parameter
	if _, exists := m.baseLevels[parameterName]; !exists {
		m.baseLevels[parameterName] = m.getCurrentLevel(parameterName)
	}

	endTime := time.Now().Add(duration)
	m.activeChanges[changeID] = &LogLevelChange{
		Level:         level,
		EndTime:       endTime,
		ChangeID:      changeID,
		ParameterName: parameterName,
	}

	// Apply the change immediately
	m.applyChanges()
	return nil
}

// RemoveChange removes a temporary log level change
func (m *LogLevelManager) RemoveChange(changeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.activeChanges, changeID)
	m.applyChanges()
}

// GetActiveChanges returns a copy of all active changes
func (m *LogLevelManager) GetActiveChanges() []*LogLevelChange {
	m.mu.RLock()
	defer m.mu.RUnlock()

	changes := make([]*LogLevelChange, 0, len(m.activeChanges))
	for _, change := range m.activeChanges {
		// Create a copy to avoid race conditions
		changeCopy := *change
		changes = append(changes, &changeCopy)
	}
	return changes
}

// applyChanges applies the current set of active changes to the log level
// Must be called with lock held
func (m *LogLevelManager) applyChanges() {
	// Collect all parameters that have either base levels or active changes
	affectedParams := make(map[string]bool)
	for paramName := range m.baseLevels {
		affectedParams[paramName] = true
	}
	for _, change := range m.activeChanges {
		affectedParams[change.ParameterName] = true
	}

	// Process each affected parameter
	for paramName := range affectedParams {
		// Get base level for this parameter
		baseLevel, hasBase := m.baseLevels[paramName]
		if !hasBase {
			baseLevel = m.getCurrentLevel(paramName)
		}
		effectiveLevel := log.PanicLevel // Start with least verbose level

		// Find the most verbose level among all active changes for this parameter
		foundChange := false
		for _, change := range m.activeChanges {
			if change.ParameterName != paramName {
				continue
			}
			// Higher numeric values are more verbose in logrus (Trace=6 > Debug=5 > Info=4 > Warn=3)
			// We want the most verbose (highest) level among all active changes
			if change.Level > effectiveLevel {
				foundChange = true
				effectiveLevel = change.Level
			}
		}
		if !foundChange {
			// No active changes for this parameter; use base level
			effectiveLevel = baseLevel
			log.Debugf("applyChanges: no active changes for %s, using base level %v", paramName, baseLevel)
		}

		// Get current level from param system
		currentLevel := m.getCurrentLevel(paramName)

		if effectiveLevel != currentLevel {
			levelStr := effectiveLevel.String()
			if effectiveLevel == log.WarnLevel {
				levelStr = "warn"
			}

			// Update via param.Set() - existing callbacks will handle updating logrus
			if err := param.Set(paramName, levelStr); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"parameter": paramName,
					"new_level": effectiveLevel.String(),
				}).Warn("Failed to apply log level change")
			} else {
				log.WithFields(log.Fields{
					"parameter":      paramName,
					"previous_level": currentLevel.String(),
					"new_level":      effectiveLevel.String(),
				}).Info("Applied log level change")
			}
		}
	}

	if m.updateCh != nil {
		select {
		case m.updateCh <- struct{}{}:
		default:
		}
	}
}

// manageLogLevels is a background goroutine that checks for expired changes at their deadlines.
func (m *LogLevelManager) manageLogLevels() {
	wait := m.checkExpiredChanges()
	if wait <= 0 {
		wait = defaultCheckInterval
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-timer.C:
		case <-m.updateCh:
		}

		wait = m.checkExpiredChanges()
		if wait <= 0 {
			wait = defaultCheckInterval
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
	}
}

// checkExpiredChanges removes expired log level changes, recomputes levels, and returns time until next deadline.
func (m *LogLevelManager) checkExpiredChanges() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	changes := make([]*LogLevelChange, 0, len(m.activeChanges))
	for _, change := range m.activeChanges {
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].EndTime.Before(changes[j].EndTime)
	})

	hasExpired := false
	for _, change := range changes {
		if now.After(change.EndTime) {
			delete(m.activeChanges, change.ChangeID)
			hasExpired = true
			log.WithFields(log.Fields{
				"change_id": change.ChangeID,
				"parameter": change.ParameterName,
				"level":     change.Level.String(),
			}).Debug("Expired temporary log level change")
			continue
		}
		// Sorted slice means the first non-expired entry has the earliest deadline.
		break
	}

	if hasExpired {
		m.applyChanges()
	}

	var nextDeadline time.Time
	hasDeadline := false
	for _, change := range m.activeChanges {
		if !hasDeadline || change.EndTime.Before(nextDeadline) {
			nextDeadline = change.EndTime
			hasDeadline = true
		}
	}

	if !hasDeadline {
		return defaultCheckInterval
	}

	return time.Until(nextDeadline)
}

// Shutdown stops the log level manager
func (m *LogLevelManager) Shutdown() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.egrp != nil {
		_ = m.egrp.Wait()
	}
}

// getParamValue uses reflection to get a string value from the param.Config struct by parameter name
// e.g., "Logging.Cache.Ofs" -> config.Logging.Cache.Ofs
func getParamValue(paramName string) string {
	config, err := param.GetUnmarshaledConfig()
	if err != nil || config == nil {
		return ""
	}

	// Split parameter name into parts (e.g., "Logging.Cache.Ofs" -> ["Logging", "Cache", "Ofs"])
	parts := strings.Split(paramName, ".")

	// Start with the config struct
	val := reflect.ValueOf(config).Elem()

	// Walk through each part to navigate the struct
	for _, part := range parts {
		if !val.IsValid() {
			return ""
		}

		// Get the field by name (case-insensitive matching like viper)
		field := val.FieldByNameFunc(func(name string) bool {
			return strings.EqualFold(name, part)
		})

		if !field.IsValid() {
			return ""
		}

		val = field
	}

	// Convert the final value to string
	if val.Kind() == reflect.String {
		return val.String()
	}

	return ""
}

// getCurrentLevel reads the current level for a parameter from the param system
func (m *LogLevelManager) getCurrentLevel(paramName string) log.Level {
	// For Logging.Level, we can also check logrus directly as a fallback
	if paramName == "Logging.Level" {
		// Try to get from param system first
		levelStr := param.Logging_Level.GetString()
		if levelStr != "" {
			level, err := log.ParseLevel(levelStr)
			if err == nil {
				return level
			}
		}
		// Fallback to logrus current level
		return log.GetLevel()
	}

	// For other parameters, try param system
	levelStr := getParamValue(paramName)
	if levelStr != "" {
		level, err := log.ParseLevel(levelStr)
		if err == nil {
			return level
		}
	}

	// Default to info level if not found
	return log.InfoLevel
}

// SetBaseLevel updates the base log level (called when configuration changes)
func (m *LogLevelManager) SetBaseLevel(level log.Level) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.baseLevels["Logging.Level"] = level
	m.applyChanges()
}

// GetParameterSnapshot returns the current and base levels for each parameter that has base level or active changes.
func (m *LogLevelManager) GetParameterSnapshot() map[string]struct {
	Current log.Level
	Base    log.Level
} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]struct {
		Current log.Level
		Base    log.Level
	})

	// Collect all parameters that have base levels or active changes
	affectedParams := make(map[string]bool)
	for paramName := range m.baseLevels {
		affectedParams[paramName] = true
	}
	for _, change := range m.activeChanges {
		affectedParams[change.ParameterName] = true
	}

	for paramName := range affectedParams {
		// Get base level
		baseLevel, hasBase := m.baseLevels[paramName]
		if !hasBase {
			baseLevel = m.getCurrentLevel(paramName)
		}

		// Compute current level (base + active changes)
		currentLevel := baseLevel
		for _, change := range m.activeChanges {
			if change.ParameterName == paramName && change.Level > currentLevel {
				currentLevel = change.Level
			}
		}

		result[paramName] = struct {
			Current log.Level
			Base    log.Level
		}{
			Current: currentLevel,
			Base:    baseLevel,
		}
	}

	return result
}
