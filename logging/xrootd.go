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

package logging

import (
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

// xrootdLoggingAccessor pairs a getter and setter
// for one XRootD-related logging field inside param.Config.
//
// Contract for set:
// The function must replace the field with a new value —
// it must not mutate a reference-type field in place.
// Otherwise, WithXrootdLoggingParam will modify the original
// because it only shallow-copies the Config.
type xrootdLoggingAccessor struct {
	get func(*param.Config) any
	set func(*param.Config, string)
}

// xrootdOriginLoggingAccessors is the authoritative list of param.Config fields
// that require restarting an XRootD origin when they are modified.
var xrootdOriginLoggingAccessors = map[string]xrootdLoggingAccessor{
	param.Logging_Origin_Cms.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Origin.Cms },
		set: func(c *param.Config, v string) { c.Logging.Origin.Cms = v },
	},
	param.Logging_Origin_Http.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Origin.Http },
		set: func(c *param.Config, v string) { c.Logging.Origin.Http = v },
	},
	param.Logging_Origin_Ofs.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Origin.Ofs },
		set: func(c *param.Config, v string) { c.Logging.Origin.Ofs = v },
	},
	param.Logging_Origin_Oss.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Origin.Oss },
		set: func(c *param.Config, v string) { c.Logging.Origin.Oss = v },
	},
	param.Logging_Origin_Scitokens.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Origin.Scitokens },
		set: func(c *param.Config, v string) { c.Logging.Origin.Scitokens = v },
	},
	param.Logging_Origin_Xrd.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Origin.Xrd },
		set: func(c *param.Config, v string) { c.Logging.Origin.Xrd = v },
	},
	param.Logging_Origin_Xrootd.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Origin.Xrootd },
		set: func(c *param.Config, v string) { c.Logging.Origin.Xrootd = v },
	},
}

// xrootdCacheLoggingAccessors is the authoritative list of param.Config fields
// that require restarting an XRootD cache when they are modified.
var xrootdCacheLoggingAccessors = map[string]xrootdLoggingAccessor{
	param.Logging_Cache_Http.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.Http },
		set: func(c *param.Config, v string) { c.Logging.Cache.Http = v },
	},
	param.Logging_Cache_Ofs.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.Ofs },
		set: func(c *param.Config, v string) { c.Logging.Cache.Ofs = v },
	},
	param.Logging_Cache_Pfc.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.Pfc },
		set: func(c *param.Config, v string) { c.Logging.Cache.Pfc = v },
	},
	param.Logging_Cache_Pss.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.Pss },
		set: func(c *param.Config, v string) { c.Logging.Cache.Pss = v },
	},
	param.Logging_Cache_PssSetOpt.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.PssSetOpt },
		set: func(c *param.Config, v string) { c.Logging.Cache.PssSetOpt = v },
	},
	param.Logging_Cache_Scitokens.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.Scitokens },
		set: func(c *param.Config, v string) { c.Logging.Cache.Scitokens = v },
	},
	param.Logging_Cache_Xrd.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.Xrd },
		set: func(c *param.Config, v string) { c.Logging.Cache.Xrd = v },
	},
	param.Logging_Cache_Xrootd.GetName(): {
		get: func(c *param.Config) any { return c.Logging.Cache.Xrootd },
		set: func(c *param.Config, v string) { c.Logging.Cache.Xrootd = v },
	},
}

// logLevelChanged reports whether
// two config field values represent a meaningful change.
func logLevelChanged(oldVal, newVal any) bool {
	oldStr, oldIsStr := oldVal.(string)
	newStr, newIsStr := newVal.(string)
	if oldIsStr && newIsStr {
		oldLv, oldErr := log.ParseLevel(oldStr)
		newLv, newErr := log.ParseLevel(newStr)
		if oldErr != nil || newErr != nil {
			return oldStr != newStr
		}
		return oldLv != newLv
	}
	return !reflect.DeepEqual(oldVal, newVal)
}

// DetectXrootdLoggingChange reports whether
// any XRootD logging parameters differ between oldConfig and newConfig,
// indicating that a restart of the XRootD origin or cache daemon
// is required to pick up the change.
func DetectXrootdLoggingChange(oldConfig, newConfig *param.Config) (originChanged, cacheChanged bool) {
	for _, acc := range xrootdOriginLoggingAccessors {
		if logLevelChanged(acc.get(oldConfig), acc.get(newConfig)) {
			originChanged = true
			break
		}
	}
	for _, acc := range xrootdCacheLoggingAccessors {
		if logLevelChanged(acc.get(oldConfig), acc.get(newConfig)) {
			cacheChanged = true
			break
		}
	}
	return
}

// WithXrootdLoggingParam returns a shallow copy of base
// with the named XRootD logging parameter set to value,
// along with a boolean indicating whether the parameter is
// an XRootD logging parameter that might require a restart when changed.
// If not, the returned config is nil and the boolean is false.
func WithXrootdLoggingParam(base *param.Config, paramName, value string) (*param.Config, bool) {
	proposed := *base  // shallow copy; see doc comment on xrootdLoggingAccessor for safety constraints

	if acc, ok := xrootdOriginLoggingAccessors[paramName]; ok {
		acc.set(&proposed, value)
		return &proposed, true
	}
	if acc, ok := xrootdCacheLoggingAccessors[paramName]; ok {
		acc.set(&proposed, value)
		return &proposed, true
	}
	return nil, false
}
