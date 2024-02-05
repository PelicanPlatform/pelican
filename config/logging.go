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

	RegexpFilterHook struct {
		filters atomic.Pointer[[]*RegexpFilter]
	}
)

var (
	globalFilters RegexpFilterHook
)

func (fh *RegexpFilterHook) Levels() []log.Level {
	return log.AllLevels
}

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

func initFilterLogging() {
	filters := make([]*RegexpFilter, 0)
	globalFilters.filters.Store(&filters)
	log.AddHook(&globalFilters)
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
