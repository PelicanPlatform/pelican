//go:build lotman_legacy_api

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

// This file is selected with `-tags lotman_legacy_api` and exports the eviction
// queries and lotman_update_lot_usage_by_dir at the OLDER lotman C ABI
// (lotman v0.0.4, used by xrootd-lotman v0.0.5):
//
//	get_lots_past_del/exp(bool recursive, char ***output, char **err_msg)
//	get_lots_past_opp/ded/obj(bool recursive_quota, bool recursive_children, char ***output, char **err_msg)
//	update_lot_usage_by_dir(const char *update_JSON_str, bool delta_mode, char **err_msg)
//
// These lack the query_time / include_reclaimed / hierarchical parameters that
// v0.1.0 added, so calling a v0.1.0-ABI library from a v0.0.5 plugin shifts the
// arguments and leaves the plugin's output pointer unset (a crash). Build this
// variant when the deployed libXrdPurgeLotMan was compiled against the old API.
// Dropped parameters default to "now" (query_time) and false
// (include_reclaimed / hierarchical), matching the old library's behavior.

package main

/*
#include <stdbool.h>
*/
import "C"

import "time"

func nowMs() int64 { return time.Now().UnixMilli() }

//export lotman_get_lots_past_exp
func lotman_get_lots_past_exp(recursive C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastExp(nowMs(), bool(recursive), false)
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_del
func lotman_get_lots_past_del(recursive C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastDel(nowMs(), bool(recursive), false)
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_opp
func lotman_get_lots_past_opp(recursiveQuota, recursiveChildren C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastOpp(bool(recursiveQuota), bool(recursiveChildren), false, false)
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_ded
func lotman_get_lots_past_ded(recursiveQuota, recursiveChildren C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastDed(bool(recursiveQuota), bool(recursiveChildren), false, false)
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_past_obj
func lotman_get_lots_past_obj(recursiveQuota, recursiveChildren C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsPastObj(bool(recursiveQuota), bool(recursiveChildren), false, false)
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_update_lot_usage_by_dir
func lotman_update_lot_usage_by_dir(updateJSON *C.char, deltaMode C._Bool, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	entries, err := parseDirUsage(C.GoString(updateJSON))
	if err != nil {
		return fail(errMsg, err)
	}
	if err := m.UpdateLotUsageByDir(entries, bool(deltaMode), nowMs(), caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}
