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
*/
import "C"

import (
	"errors"
	"unsafe"
)

// This file provides a thin Go-typed mirror of the C ABI. cgo cannot be used
// directly from _test.go files, so these helpers let the in-process tests (and
// any Go caller that links this package) drive the exported functions with Go
// types instead of raw C pointers. They are unexported and unreferenced by the
// exported C entry points, so the linker drops them from the built shared
// library; they add nothing to the C ABI.

// errFromMsg interprets a (return-code, err_msg) pair: a negative code yields an
// error carrying the freed message; otherwise nil.
func errFromMsg(rc C.int, errMsg *C.char) error {
	if rc >= 0 {
		if errMsg != nil {
			C.free(unsafe.Pointer(errMsg))
		}
		return nil
	}
	msg := "lotman error"
	if errMsg != nil {
		msg = C.GoString(errMsg)
		C.free(unsafe.Pointer(errMsg))
	}
	return errors.New(msg)
}

func withCStr(s string, fn func(*C.char)) {
	c := C.CString(s)
	defer C.free(unsafe.Pointer(c))
	fn(c)
}

func setContextStrGo(key, value string) {
	k := C.CString(key)
	defer C.free(unsafe.Pointer(k))
	v := C.CString(value)
	defer C.free(unsafe.Pointer(v))
	var e *C.char
	rc := lotman_set_context_str(k, v, &e)
	_ = errFromMsg(rc, e)
}

func addLotGo(jsonStr string) error {
	var err error
	withCStr(jsonStr, func(c *C.char) {
		var e *C.char
		err = errFromMsg(lotman_add_lot(c, &e), e)
	})
	return err
}

func lotExistsGo(name string) (int, error) {
	var rc C.int
	var err error
	withCStr(name, func(c *C.char) {
		var e *C.char
		rc = lotman_lot_exists(c, &e)
		err = errFromMsg(rc, e)
	})
	return int(rc), err
}

func isRootGo(name string) (int, error) {
	var rc C.int
	var err error
	withCStr(name, func(c *C.char) {
		var e *C.char
		rc = lotman_is_root(c, &e)
		err = errFromMsg(rc, e)
	})
	return int(rc), err
}

func listAllLotsGo() ([]string, error) {
	var list **C.char
	var e *C.char
	if err := errFromMsg(lotman_list_all_lots(&list, &e), e); err != nil {
		return nil, err
	}
	out := goStringSlice(list)
	lotman_free_string_list(list)
	return out, nil
}

func getLotAsJSONGo(name string, recursive bool) (string, error) {
	var out *C.char
	var err error
	withCStr(name, func(c *C.char) {
		var e *C.char
		err = errFromMsg(lotman_get_lot_as_json(c, C._Bool(recursive), &out, &e), e)
	})
	if err != nil {
		return "", err
	}
	s := C.GoString(out)
	C.free(unsafe.Pointer(out))
	return s, nil
}

func updateLotUsageGo(jsonStr string, delta bool) error {
	var err error
	withCStr(jsonStr, func(c *C.char) {
		var e *C.char
		err = errFromMsg(lotman_update_lot_usage(c, C._Bool(delta), &e), e)
	})
	return err
}

func getLotUsageGo(jsonStr string) (string, error) {
	var out *C.char
	var err error
	withCStr(jsonStr, func(c *C.char) {
		var e *C.char
		err = errFromMsg(lotman_get_lot_usage(c, &out, &e), e)
	})
	if err != nil {
		return "", err
	}
	s := C.GoString(out)
	C.free(unsafe.Pointer(out))
	return s, nil
}

func versionGo() string {
	return C.GoString(lotman_version())
}

// goStringSlice copies a NULL-terminated C string array into a Go slice.
func goStringSlice(list **C.char) []string {
	if list == nil {
		return nil
	}
	var out []string
	ptrSize := unsafe.Sizeof((*C.char)(nil))
	for p := unsafe.Pointer(list); ; p = unsafe.Add(p, ptrSize) {
		s := *(**C.char)(p)
		if s == nil {
			break
		}
		out = append(out, C.GoString(s))
	}
	return out
}

// resetStateForTest clears the process-global manager and context so each test
// starts from a clean slate.
func resetStateForTest() {
	mgrMu.Lock()
	mgr = nil
	mgrLotHome = ""
	mgrMu.Unlock()
	ctxMu.Lock()
	ctxStr = map[string]string{}
	ctxInt = map[string]int{}
	ctxMu.Unlock()
}
