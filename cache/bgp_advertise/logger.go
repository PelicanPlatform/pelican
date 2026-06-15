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

package bgp_advertise

import (
	bgplog "github.com/osrg/gobgp/v3/pkg/log"
	log "github.com/sirupsen/logrus"
)

// bgpLogger bridges GoBGP's logging interface to Pelican's logrus logger,
// tagging every line with a "component=bgp" field.  GoBGP's Info-level chatter
// (session state transitions, etc.) is mapped down to Debug to avoid flooding
// the cache logs; warnings and errors are preserved.
type bgpLogger struct {
	entry *log.Entry
}

func newLogger() *bgpLogger {
	return &bgpLogger{entry: log.WithField("component", "bgp")}
}

func (l *bgpLogger) withFields(fields bgplog.Fields) *log.Entry {
	if len(fields) == 0 {
		return l.entry
	}
	return l.entry.WithFields(log.Fields(fields))
}

func (l *bgpLogger) Panic(msg string, fields bgplog.Fields) { l.withFields(fields).Panic(msg) }
func (l *bgpLogger) Fatal(msg string, fields bgplog.Fields) { l.withFields(fields).Error(msg) }
func (l *bgpLogger) Error(msg string, fields bgplog.Fields) { l.withFields(fields).Error(msg) }
func (l *bgpLogger) Warn(msg string, fields bgplog.Fields)  { l.withFields(fields).Warn(msg) }
func (l *bgpLogger) Info(msg string, fields bgplog.Fields)  { l.withFields(fields).Debug(msg) }
func (l *bgpLogger) Debug(msg string, fields bgplog.Fields) { l.withFields(fields).Trace(msg) }

func (l *bgpLogger) SetLevel(level bgplog.LogLevel) {}

func (l *bgpLogger) GetLevel() bgplog.LogLevel {
	switch log.GetLevel() {
	case log.PanicLevel:
		return bgplog.PanicLevel
	case log.FatalLevel:
		return bgplog.FatalLevel
	case log.ErrorLevel:
		return bgplog.ErrorLevel
	case log.WarnLevel:
		return bgplog.WarnLevel
	case log.InfoLevel:
		return bgplog.InfoLevel
	default:
		return bgplog.DebugLevel
	}
}
