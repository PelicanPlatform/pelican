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

package main

/*
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/pelicanplatform/pelican/lotman/core"
	"github.com/pelicanplatform/pelican/lotman/lotjson"
)

func main() {}

// versionC is allocated once and never freed, matching the "static const char *"
// lifetime the original lotman_version exposed.
var versionC = C.CString(lotmanVersion)

// --- C memory / error helpers -------------------------------------------------

// fail stores err's message in *errMsg (newly C-allocated; caller frees) and
// returns -1, the library's generic error code.
func fail(errMsg **C.char, err error) C.int {
	if errMsg != nil {
		*errMsg = C.CString(err.Error())
	}
	return -1
}

// putString writes a single C string (caller frees) into *out.
func putString(out **C.char, s string) {
	if out != nil {
		*out = C.CString(s)
	}
}

// putJSON marshals v and writes it as a C string into *out.
func putJSON(out **C.char, errMsg **C.char, v any) C.int {
	b, err := json.Marshal(v)
	if err != nil {
		return fail(errMsg, err)
	}
	putString(out, string(b))
	return 0
}

// putStringList writes list as a NULL-terminated array of C strings into *out,
// freeable with lotman_free_string_list.
func putStringList(out ***C.char, list []string) {
	if out == nil {
		return
	}
	ptrSize := unsafe.Sizeof((*C.char)(nil))
	arr := C.malloc(C.size_t(uintptr(len(list)+1) * ptrSize))
	view := unsafe.Slice((**C.char)(arr), len(list)+1)
	for i, s := range list {
		view[i] = C.CString(s)
	}
	view[len(list)] = nil
	*out = (**C.char)(arr)
}

//export lotman_free_string_list
func lotman_free_string_list(strList **C.char) {
	if strList == nil {
		return
	}
	ptrSize := unsafe.Sizeof((*C.char)(nil))
	for p := unsafe.Pointer(strList); ; p = unsafe.Add(p, ptrSize) {
		s := *(**C.char)(p)
		if s == nil {
			break
		}
		C.free(unsafe.Pointer(s))
	}
	C.free(unsafe.Pointer(strList))
}

//export lotman_version
func lotman_version() *C.char {
	return versionC
}

// --- lifecycle: create / update / add / remove --------------------------------

//export lotman_add_lot
func lotman_add_lot(lotmanJSON *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var l lotjson.Lot
	if err := json.Unmarshal([]byte(C.GoString(lotmanJSON)), &l); err != nil {
		return fail(errMsg, err)
	}
	if err := m.AddLot(lotjson.LotToSpec(&l), caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}

//export lotman_update_lot
func lotman_update_lot(lotmanJSON *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var u lotjson.LotUpdate
	if err := json.Unmarshal([]byte(C.GoString(lotmanJSON)), &u); err != nil {
		return fail(errMsg, err)
	}

	// Owner / MPA / parent-attribution changes go through the core update. A
	// non-nil MPA is merged onto the lot's existing MPA so unspecified fields
	// (notably creation_time) are preserved.
	if u.Owner != nil || u.MPA != nil || u.ParentAttributions != nil {
		cu := core.LotUpdate{
			LotName:            u.LotName,
			Owner:              u.Owner,
			ParentAttributions: lotjson.ParentAttrToCore(u.ParentAttributions),
		}
		if u.MPA != nil {
			existing, err := m.GetLot(u.LotName)
			if err != nil {
				return fail(errMsg, err)
			}
			mpa := lotjson.MergeMPAToCore(u.MPA, existing.Lot)
			cu.MPA = &mpa
		}
		if err := m.UpdateLot(cu, caller()); err != nil {
			return fail(errMsg, err)
		}
	}

	// Path "renames": add-new then remove-old (the core update does not replace
	// paths in place).
	if u.Paths != nil {
		for _, pu := range *u.Paths {
			if err := m.AddToLot(core.LotAddition{LotName: u.LotName, Paths: []core.PathSpec{{Path: pu.New, Recursive: pu.Recursive}}}, caller()); err != nil {
				return fail(errMsg, err)
			}
			if err := m.RemovePaths(core.LotPathRemoval{LotName: u.LotName, Paths: []string{pu.Current}}, caller()); err != nil {
				return fail(errMsg, err)
			}
		}
	}

	// Parent "renames": add the new parent before removing the old to keep the
	// at-least-one-parent invariant.
	if u.Parents != nil {
		for _, pu := range *u.Parents {
			if err := m.AddToLot(core.LotAddition{LotName: u.LotName, Parents: []string{pu.New}}, caller()); err != nil {
				return fail(errMsg, err)
			}
			if err := m.RemoveParents(core.LotParentRemoval{LotName: u.LotName, Parents: []string{pu.Current}}, caller()); err != nil {
				return fail(errMsg, err)
			}
		}
	}
	return 0
}

//export lotman_add_to_lot
func lotman_add_to_lot(additionsJSON *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var a lotjson.LotAddition
	if err := json.Unmarshal([]byte(C.GoString(additionsJSON)), &a); err != nil {
		return fail(errMsg, err)
	}
	add := core.LotAddition{
		LotName:            a.LotName,
		Parents:            a.Parents,
		Paths:              lotjson.PathSpecsFromLotPaths(a.Paths),
		ParentAttributions: lotjson.ParentAttrToCore(a.ParentAttributions),
	}
	if err := m.AddToLot(add, caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}

//export lotman_remove_lot
func lotman_remove_lot(lotName *C.char, assignLTBRParentToOrphans, assignLTBRParentToNonOrphans, assignPolicyToChildren, overridePolicy C._Bool, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	// The native core preserves children by reparenting them to the removed
	// lot's parents, matching the legacy reassignment flags' intent.
	if err := m.RemoveLot(C.GoString(lotName), core.RemoveOptions{}, caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}

//export lotman_remove_lots_recursive
func lotman_remove_lots_recursive(lotName *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	if err := m.RemoveLotRecursive(C.GoString(lotName), caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}

//export lotman_rm_parents_from_lot
func lotman_rm_parents_from_lot(removeParentsJSON *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var r lotjson.LotParentRemoval
	if err := json.Unmarshal([]byte(C.GoString(removeParentsJSON)), &r); err != nil {
		return fail(errMsg, err)
	}
	if err := m.RemoveParents(core.LotParentRemoval{LotName: r.LotName, Parents: r.Parents}, caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}

//export lotman_rm_paths_from_lots
func lotman_rm_paths_from_lots(removeDirsJSON *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var r lotjson.LotPathRemoval
	if err := json.Unmarshal([]byte(C.GoString(removeDirsJSON)), &r); err != nil {
		return fail(errMsg, err)
	}
	// A path belongs to at most one lot; resolve the owning lot per path.
	for _, p := range r.Paths {
		owner, err := m.LotForPath(p)
		if err != nil {
			return fail(errMsg, err)
		}
		if owner == "" {
			continue
		}
		if err := m.RemovePaths(core.LotPathRemoval{LotName: owner, Paths: []string{p}}, caller()); err != nil {
			return fail(errMsg, err)
		}
	}
	return 0
}

//export lotman_reclaim_lot
func lotman_reclaim_lot(lotName *C.char, reclaimedAt C.int64_t, reason *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	res, err := m.ReclaimLot(C.GoString(lotName), int64(reclaimedAt), C.GoString(reason), caller())
	if err != nil {
		return fail(errMsg, err)
	}
	return C.int(int(res))
}

// --- predicates ---------------------------------------------------------------

//export lotman_lot_exists
func lotman_lot_exists(lotName *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	exists, err := m.LotExists(C.GoString(lotName))
	if err != nil {
		return fail(errMsg, err)
	}
	if exists {
		return 1
	}
	return 0
}

//export lotman_is_root
func lotman_is_root(lotName *C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	isRoot, err := m.IsRoot(C.GoString(lotName))
	if err != nil {
		return fail(errMsg, err)
	}
	if isRoot {
		return 1
	}
	return 0
}

// --- name / relationship queries (string-list output) -------------------------

//export lotman_get_owners
func lotman_get_owners(lotName *C.char, recursive C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	owners, err := m.GetOwners(C.GoString(lotName), bool(recursive))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, owners)
	return 0
}

//export lotman_get_parent_names
func lotman_get_parent_names(lotName *C.char, recursive, getSelf C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	parents, err := m.GetParents(C.GoString(lotName), bool(recursive), bool(getSelf))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, parents)
	return 0
}

//export lotman_get_children_names
func lotman_get_children_names(lotName *C.char, recursive, getSelf C._Bool, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	children, err := m.GetChildren(C.GoString(lotName), bool(recursive), bool(getSelf))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, children)
	return 0
}

//export lotman_list_all_lots
func lotman_list_all_lots(output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	names, err := m.ListAllLots()
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, names)
	return 0
}

//export lotman_get_lots_from_dir
func lotman_get_lots_from_dir(dir *C.char, recursive C._Bool, queryTime C.int64_t, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsFromDir(C.GoString(dir), bool(recursive), int64(queryTime))
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

//export lotman_get_lots_for_path
func lotman_get_lots_for_path(path *C.char, recursive C._Bool, timeLoMs, timeHiMs C.int64_t, output ***C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lots, err := m.LotsForPath(C.GoString(path), bool(recursive), int64(timeLoMs), int64(timeHiMs), false)
	if err != nil {
		return fail(errMsg, err)
	}
	putStringList(output, lots)
	return 0
}

// --- eviction-priority queries ------------------------------------------------

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

// --- JSON-document queries (single-string output) -----------------------------

// buildLotJSON mirrors the adapter's GetLot: a lot view plus its parents,
// owners and parent attributions, and (when recursive) the most-restrictive
// hierarchical MPA.
func buildLotJSON(m *core.Manager, name string, recursive bool) (*lotjson.Lot, error) {
	v, err := m.GetLot(name)
	if err != nil {
		return nil, err
	}
	lot := lotjson.LotViewToAdapter(v)
	parents, err := m.GetParents(name, recursive, true)
	if err != nil {
		return nil, err
	}
	lot.Parents = parents
	owners, err := m.GetOwners(name, recursive)
	if err != nil {
		return nil, err
	}
	lot.Owners = owners
	attrs, err := m.Attributions(name)
	if err != nil {
		return nil, err
	}
	lot.ParentAttributions = lotjson.AttrValuesToAdapter(attrs)
	if recursive {
		rv, err := m.PolicyAttributes(core.PolicyAttrsRequest{LotName: name, Recursive: true})
		if err != nil {
			return nil, err
		}
		lot.RestrictiveMPA = lotjson.RestrictiveToAdapter(rv)
	}
	return lot, nil
}

//export lotman_get_lot_as_json
func lotman_get_lot_as_json(lotName *C.char, recursive C._Bool, output **C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	lot, err := buildLotJSON(m, C.GoString(lotName), bool(recursive))
	if err != nil {
		return fail(errMsg, err)
	}
	return putJSON(output, errMsg, lot)
}

//export lotman_get_lot_dirs
func lotman_get_lot_dirs(lotName *C.char, recursive C._Bool, output **C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	name := C.GoString(lotName)
	v, err := m.GetLot(name)
	if err != nil {
		return fail(errMsg, err)
	}
	paths := []lotjson.LotPath{}
	for _, p := range v.Paths {
		paths = append(paths, lotjson.LotPath{Path: p.Path, Recursive: p.Recursive, LotName: name})
	}
	if bool(recursive) {
		children, err := m.GetChildren(name, true, false)
		if err != nil {
			return fail(errMsg, err)
		}
		for _, c := range children {
			cv, err := m.GetLot(c)
			if err != nil {
				return fail(errMsg, err)
			}
			for _, p := range cv.Paths {
				paths = append(paths, lotjson.LotPath{Path: p.Path, Recursive: p.Recursive, LotName: c})
			}
		}
	}
	return putJSON(output, errMsg, paths)
}

//export lotman_get_lot_usage
func lotman_get_lot_usage(usageJSON *C.char, output **C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var req lotjson.UsageRequest
	if err := json.Unmarshal([]byte(C.GoString(usageJSON)), &req); err != nil {
		return fail(errMsg, err)
	}
	v, err := m.GetLot(req.LotName)
	if err != nil {
		return fail(errMsg, err)
	}
	return putJSON(output, errMsg, lotjson.UsageRowToLotUsage(v.Usage, v.Lot))
}

//export lotman_get_policy_attributes
func lotman_get_policy_attributes(policyJSON *C.char, output **C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var req lotjson.PolicyAttrsRequest
	if err := json.Unmarshal([]byte(C.GoString(policyJSON)), &req); err != nil {
		return fail(errMsg, err)
	}
	keys := []string{}
	if req.DedicatedGB {
		keys = append(keys, core.MpaKeyDedicatedBytes)
	}
	if req.OpportunisticGB {
		keys = append(keys, core.MpaKeyOpportunisticBytes)
	}
	if req.MaxNumObjects {
		keys = append(keys, core.MpaKeyMaxNumObjects)
	}
	if req.CreationTime {
		keys = append(keys, "creation_time")
	}
	if req.ExpirationTime {
		keys = append(keys, "expiration_time")
	}
	if req.DeletionTime {
		keys = append(keys, "deletion_time")
	}
	rv, err := m.PolicyAttributes(core.PolicyAttrsRequest{LotName: req.LotName, Recursive: true, Keys: keys})
	if err != nil {
		return fail(errMsg, err)
	}
	return putJSON(output, errMsg, lotjson.RestrictiveToAdapter(rv))
}

//export lotman_get_available_capacity
func lotman_get_available_capacity(parentLot *C.char, startTime, endTime C.int64_t, output **C.char, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	c, err := m.AvailableCapacity(C.GoString(parentLot), int64(startTime), int64(endTime))
	if err != nil {
		return fail(errMsg, err)
	}
	return putJSON(output, errMsg, lotjson.CapacityToAdapter(c))
}

// --- usage updates ------------------------------------------------------------

//export lotman_update_lot_usage
func lotman_update_lot_usage(updateJSON *C.char, deltaMode C._Bool, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var in struct {
		LotName                 string   `json:"lot_name"`
		SelfGB                  *float64 `json:"self_GB"`
		SelfObjects             *int64   `json:"self_objects"`
		SelfGBBeingWritten      *float64 `json:"self_GB_being_written"`
		SelfObjectsBeingWritten *int64   `json:"self_objects_being_written"`
	}
	if err := json.Unmarshal([]byte(C.GoString(updateJSON)), &in); err != nil {
		return fail(errMsg, err)
	}
	u := core.UsageUpdate{LotName: in.LotName, SelfObjects: in.SelfObjects, SelfObjectsBeingWritten: in.SelfObjectsBeingWritten}
	if in.SelfGB != nil {
		b := lotjson.GbToBytes(*in.SelfGB)
		u.SelfBytes = &b
	}
	if in.SelfGBBeingWritten != nil {
		b := lotjson.GbToBytes(*in.SelfGBBeingWritten)
		u.SelfBytesBeingWritten = &b
	}
	if err := m.UpdateLotUsage(u, bool(deltaMode), caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}

type dirUsageNode struct {
	Path    string         `json:"path"`
	SizeGB  *float64       `json:"size_GB"`
	NumObj  *int64         `json:"num_obj"`
	Subdirs []dirUsageNode `json:"subdirs"`
}

//export lotman_update_lot_usage_by_dir
func lotman_update_lot_usage_by_dir(updateJSON *C.char, deltaMode C._Bool, queryTime C.int64_t, errMsg **C.char) C.int {
	m, err := manager()
	if err != nil {
		return fail(errMsg, err)
	}
	var nodes []dirUsageNode
	if err := json.Unmarshal([]byte(C.GoString(updateJSON)), &nodes); err != nil {
		return fail(errMsg, err)
	}
	var entries []core.DirUsage
	var walk func(n dirUsageNode)
	walk = func(n dirUsageNode) {
		e := core.DirUsage{Path: n.Path}
		if n.SizeGB != nil {
			e.SizeBytes = lotjson.GbToBytes(*n.SizeGB)
		}
		if n.NumObj != nil {
			e.NumObjects = *n.NumObj
		}
		entries = append(entries, e)
		for _, c := range n.Subdirs {
			walk(c)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	if err := m.UpdateLotUsageByDir(entries, bool(deltaMode), int64(queryTime), caller()); err != nil {
		return fail(errMsg, err)
	}
	return 0
}

// --- context ------------------------------------------------------------------

//export lotman_set_context_str
func lotman_set_context_str(key, value *C.char, errMsg **C.char) C.int {
	setContextStr(C.GoString(key), C.GoString(value))
	return 0
}

//export lotman_get_context_str
func lotman_get_context_str(key *C.char, output **C.char, errMsg **C.char) C.int {
	v, _ := getContextStr(C.GoString(key))
	putString(output, v)
	return 0
}

//export lotman_set_context_int
func lotman_set_context_int(key *C.char, value C.int, errMsg **C.char) C.int {
	setContextInt(C.GoString(key), int(value))
	return 0
}

//export lotman_get_context_int
func lotman_get_context_int(key *C.char, output *C.int, errMsg **C.char) C.int {
	v, _ := getContextInt(C.GoString(key))
	if output != nil {
		*output = C.int(v)
	}
	return 0
}
