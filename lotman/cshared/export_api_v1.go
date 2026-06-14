//go:build !lotman_legacy_api

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

// This file holds the eviction-priority queries and lotman_update_lot_usage_by_dir
// at their CURRENT lotman C ABI (v0.1.0+), where get_lots_past_del/exp take a
// query_time and include_reclaimed, get_lots_past_opp/ded/obj take
// include_reclaimed and hierarchical, and update_lot_usage_by_dir takes a
// query_time. This is the default build; pass -tags lotman_legacy_api to export
// the older (lotman v0.0.4 / xrootd-lotman v0.0.5) signatures instead. See
// export_api_legacy.go.

package main

/*
#include <stdbool.h>
#include <stdint.h>
*/
import "C"

//export lotman_get_lots_past_exp
func lotman_get_lots_past_exp(queryTime C.int64_t, recursive, includeReclaimed C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastExp(int64(queryTime), bool(recursive), bool(includeReclaimed))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_del
func lotman_get_lots_past_del(queryTime C.int64_t, recursive, includeReclaimed C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastDel(int64(queryTime), bool(recursive), bool(includeReclaimed))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_opp
func lotman_get_lots_past_opp(recursiveQuota, recursiveChildren, includeReclaimed C._Bool, output ***C.char, hierarchical C._Bool, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastOpp(bool(recursiveQuota), bool(recursiveChildren), bool(includeReclaimed), bool(hierarchical))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_ded
func lotman_get_lots_past_ded(recursiveQuota, recursiveChildren, includeReclaimed C._Bool, output ***C.char, hierarchical C._Bool, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastDed(bool(recursiveQuota), bool(recursiveChildren), bool(includeReclaimed), bool(hierarchical))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_obj
func lotman_get_lots_past_obj(recursiveQuota, recursiveChildren, includeReclaimed C._Bool, output ***C.char, hierarchical C._Bool, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastObj(bool(recursiveQuota), bool(recursiveChildren), bool(includeReclaimed), bool(hierarchical))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_update_lot_usage_by_dir
func lotman_update_lot_usage_by_dir(updateJSON *C.char, deltaMode C._Bool, queryTime C.int64_t, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	entries, err := parseDirUsage(C.GoString(updateJSON))
	if err != nil {
		return fail(errMsg, err)
	}
	if err := m.UpdateLotUsageByDir(entries, bool(deltaMode), int64(queryTime), caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}
