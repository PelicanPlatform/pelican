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
	"regexp"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

type (
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
		replacements []replacement
	}

	replacement struct {
		regex    *regexp.Regexp
		template string
	}
)

var (
	globalFilters      RegexpFilterHook
	addedGlobalFilters bool

	globalTransform *regexpTransformHook = &regexpTransformHook{
		replacements: []replacement{
			{
				regex:    regexp.MustCompile(`(?P<prefix>Bearer%20)?(?P<header>ey[A-Za-z0-9_=-]{18,})[.](?P<payload>ey[A-Za-z0-9_=-]{18,})[.]([A-Za-z0-9_=-]{64,})`),
				template: "$prefix$header.$payload.REDACTED",
			},
		},
	}
)

// This ensures that our hooks will be fired on all log levels
func (fh *RegexpFilterHook) Levels() []log.Level {
	return log.AllLevels
}

func (rt *regexpTransformHook) Levels() []log.Level {
	return log.AllLevels
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
	for _, replace := range rt.replacements {
		entry.Message = replace.regex.ReplaceAllString(entry.Message, replace.template)
	}
	return nil
}

func initFilterLogging() {
	filters := make([]*RegexpFilter, 0)
	globalFilters.filters.Store(&filters)

	// Unit tests may initialize the server multiple times; avoid configuring
	// the global logging multiple times
	if !addedGlobalFilters {
		log.AddHook(&globalFilters)
		addedGlobalFilters = true
		log.AddHook(globalTransform)
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
