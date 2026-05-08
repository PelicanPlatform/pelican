//go:build linux

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

package origin_serve

import (
	"context"
	"fmt"
	"maps"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/identity"
)

const (
	// multiuserComponent is the log component name for all multiuser log lines.
	multiuserComponent = "multiuser"

	// statsSummaryInterval is how often the periodic summary is logged.
	statsSummaryInterval = 5 * time.Minute
)

// multiuserLogger is a pre-configured logger entry with the component field set.
var multiuserLogger = log.WithField("component", multiuserComponent)

// resolvedID holds the identity information resolved for a single operation.
type resolvedID struct {
	Username      string
	Groupname     string
	UID           uint32
	GID           uint32
	SecondaryGIDs []uint32
}

// userOpCounts tracks per-operation counts for a single user.
type userOpCounts struct {
	Mkdir  int64
	Open   int64
	Remove int64
	Rename int64
	Stat   int64
	Errors int64
}

// opStats tracks operation statistics for the periodic summary.
type opStats struct {
	mu    sync.Mutex
	users map[string]*userOpCounts // keyed by username
}

func newOpStats() *opStats {
	return &opStats{
		users: make(map[string]*userOpCounts),
	}
}

// record increments the counter for the given user and operation.
func (s *opStats) record(username, op string, isErr bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts, ok := s.users[username]
	if !ok {
		counts = &userOpCounts{}
		s.users[username] = counts
	}
	switch op {
	case "mkdir":
		counts.Mkdir++
	case "open":
		counts.Open++
	case "remove":
		counts.Remove++
	case "rename":
		counts.Rename++
	case "stat":
		counts.Stat++
	}
	if isErr {
		counts.Errors++
	}
}

// snapshotAndReset atomically returns the current stats and resets them.
func (s *opStats) snapshotAndReset() map[string]*userOpCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.users
	s.users = make(map[string]*userOpCounts)
	return snap
}

// multiuserFileSystem wraps a webdav.FileSystem to perform filesystem
// operations as the user/group identified by the request context.
//
// Every method on webdav.FileSystem receives a context.Context, so we
// extract the userInfo directly — no goroutine-keyed state needed.
//
// The wrapper uses Linux setfsuid/setfsgid syscalls to temporarily change
// the filesystem UID/GID for the current OS thread. The goroutine is
// locked to the OS thread for the duration of each operation.
type multiuserFileSystem struct {
	inner  webdav.FileSystem
	lookup identity.Lookup
	stats  *opStats
}

// Compile-time check that multiuserFileSystem implements webdav.FileSystem.
var _ webdav.FileSystem = (*multiuserFileSystem)(nil)

// newMultiuserFileSystem creates a new multiuser filesystem wrapper.
// The provided ctx controls the lifetime of the periodic summary goroutine.
// If umask >= 0 it is applied to the process once at startup; a negative
// value (the default) leaves the inherited process umask unchanged.
func newMultiuserFileSystem(ctx context.Context, inner webdav.FileSystem, lookup identity.Lookup, umask int) (webdav.FileSystem, error) {
	if umask >= 0 {
		prev := syscall.Umask(umask)
		multiuserLogger.WithFields(log.Fields{
			"previous": fmt.Sprintf("%04o", prev),
			"new":      fmt.Sprintf("%04o", umask),
		}).Info("Set process umask for multiuser mode")
	}
	stats := newOpStats()
	mfs := &multiuserFileSystem{
		inner:  inner,
		lookup: lookup,
		stats:  stats,
	}
	go mfs.runSummaryLoop(ctx)
	return mfs, nil
}

// runSummaryLoop periodically logs an info-level summary of operations.
func (m *multiuserFileSystem) runSummaryLoop(ctx context.Context) {
	ticker := time.NewTicker(statsSummaryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			multiuserLogger.Debug("Stopping periodic summary goroutine")
			return
		case <-ticker.C:
			m.logSummary()
		}
	}
}

// logSummary logs an info-level summary of operations since the last summary.
func (m *multiuserFileSystem) logSummary() {
	snap := m.stats.snapshotAndReset()

	if len(snap) == 0 {
		multiuserLogger.Info("No multiuser filesystem operations in the last reporting period")
		return
	}

	// Sort users for deterministic output
	users := slices.Sorted(maps.Keys(snap))

	var totalOps, totalErrors int64
	var parts []string
	for _, u := range users {
		c := snap[u]
		ops := c.Mkdir + c.Open + c.Remove + c.Rename + c.Stat
		totalOps += ops
		totalErrors += c.Errors

		// Build a compact per-user summary
		var opParts []string
		if c.Open > 0 {
			opParts = append(opParts, fmt.Sprintf("open=%d", c.Open))
		}
		if c.Stat > 0 {
			opParts = append(opParts, fmt.Sprintf("stat=%d", c.Stat))
		}
		if c.Mkdir > 0 {
			opParts = append(opParts, fmt.Sprintf("mkdir=%d", c.Mkdir))
		}
		if c.Remove > 0 {
			opParts = append(opParts, fmt.Sprintf("remove=%d", c.Remove))
		}
		if c.Rename > 0 {
			opParts = append(opParts, fmt.Sprintf("rename=%d", c.Rename))
		}
		errStr := ""
		if c.Errors > 0 {
			errStr = fmt.Sprintf(", errors=%d", c.Errors)
		}
		parts = append(parts, fmt.Sprintf("%s(%s%s)", u, strings.Join(opParts, " "), errStr))
	}

	multiuserLogger.WithFields(log.Fields{
		"total_ops":    totalOps,
		"total_errors": totalErrors,
		"users":        len(snap),
	}).Infof("Operation summary: %s", strings.Join(parts, "; "))
}

// resolveIdentity extracts userInfo from the context and resolves
// the UID/GID via the identity.Lookup.
//
// It returns an error when the user is missing from the context or cannot
// be resolved.  Callers must not proceed with UID/GID 0 on failure.
func (m *multiuserFileSystem) resolveIdentity(ctx context.Context) (resolvedID, error) {
	ui := getUserInfo(ctx)
	if ui == nil || ui.User == "" {
		return resolvedID{}, fmt.Errorf("no user information in request context")
	}

	resolvedUid, err := m.lookup.UidForUser(ui.User)
	if err != nil {
		multiuserLogger.WithFields(log.Fields{
			"user":  ui.User,
			"error": err,
		}).Warn("Failed to resolve UID; denying operation")
		return resolvedID{Username: ui.User}, fmt.Errorf("failed to resolve UID for user %q: %w", ui.User, err)
	}

	var groupname string
	var resolvedGid uint32
	if len(ui.Groups) > 0 {
		groupname = ui.Groups[0]
		resolvedGid, err = m.lookup.GidForGroup(groupname)
		if err != nil {
			multiuserLogger.WithFields(log.Fields{
				"user":  ui.User,
				"group": groupname,
				"error": err,
			}).Warn("Failed to resolve GID; denying operation")
			return resolvedID{Username: ui.User}, fmt.Errorf("failed to resolve GID for group %q: %w", groupname, err)
		}
	}

	// Resolve secondary GIDs (already filtered by min-ID in the lookup layer).
	secondaryGIDs, err := m.lookup.SecondaryGidsForUser(ui.User)
	if err != nil {
		multiuserLogger.WithFields(log.Fields{
			"user":  ui.User,
			"error": err,
		}).Debug("Failed to resolve secondary GIDs")
	}

	return resolvedID{
		Username:      ui.User,
		Groupname:     groupname,
		UID:           resolvedUid,
		GID:           resolvedGid,
		SecondaryGIDs: secondaryGIDs,
	}, nil
}

// logOp emits a debug-level structured log for a filesystem operation.
func (m *multiuserFileSystem) logOp(op, path string, id resolvedID, err error) {
	entry := multiuserLogger.WithFields(log.Fields{
		"op":   op,
		"path": path,
		"user": id.Username,
		"uid":  id.UID,
		"gid":  id.GID,
	})
	if id.Groupname != "" {
		entry = entry.WithField("group", id.Groupname)
	}
	if len(id.SecondaryGIDs) > 0 {
		entry = entry.WithField("secondaryGIDs", id.SecondaryGIDs)
	}

	isErr := err != nil
	m.stats.record(id.Username, op, isErr)

	if isErr {
		entry.WithError(err).Debug("Operation failed")
	} else {
		entry.Debug("Operation completed")
	}
}

// threadSetgroups calls the setgroups(2) syscall directly via RawSyscall,
// which only affects the current OS thread (unlike syscall.Setgroups which
// uses the Go runtime's all-threads mechanism).  The caller MUST have
// called runtime.LockOSThread() beforehand.
func threadSetgroups(gids []uint32) error {
	if len(gids) == 0 {
		_, _, errno := syscall.RawSyscall(syscall.SYS_SETGROUPS, 0, 0, 0)
		if errno != 0 {
			return fmt.Errorf("setgroups(0): %w", errno)
		}
		return nil
	}
	_, _, errno := syscall.RawSyscall(syscall.SYS_SETGROUPS, uintptr(len(gids)), uintptr(unsafe.Pointer(&gids[0])), 0)
	if errno != 0 {
		return fmt.Errorf("setgroups(%d): %w", len(gids), errno)
	}
	return nil
}

// threadGetgroups retrieves the current thread's supplementary group list
// via the raw getgroups(2) syscall.
func threadGetgroups() ([]uint32, error) {
	// First call with size=0 to get count.
	n, _, errno := syscall.RawSyscall(syscall.SYS_GETGROUPS, 0, 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("getgroups(0): %w", errno)
	}
	count := int(n)
	if count == 0 {
		return nil, nil
	}
	gids := make([]uint32, count)
	_, _, errno = syscall.RawSyscall(syscall.SYS_GETGROUPS, uintptr(count), uintptr(unsafe.Pointer(&gids[0])), 0)
	if errno != 0 {
		return nil, fmt.Errorf("getgroups(%d): %w", count, errno)
	}
	return gids, nil
}

// runAsUser executes fn with the filesystem UID/GID and supplementary groups
// temporarily set to the given values. The goroutine is locked to the OS
// thread for the duration.
//
// Order of operations:
//   - Save and set supplementary groups (while we still have root UID)
//   - Set GID (while we still have root UID privileges)
//   - Set UID (dropping privileges for FS operations)
//   - Execute fn
//   - Restore UID first (regaining privileges)
//   - Restore GID
//   - Restore supplementary groups
func runAsUser[T any](uid, gid uint32, secondaryGIDs []uint32, fn func() (T, error)) (T, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save and set supplementary groups first (while we have root privileges).
	prevGroups, err := threadGetgroups()
	if err != nil {
		var zero T
		return zero, fmt.Errorf("failed to get supplementary groups: %w", err)
	}
	// Always set groups — pass empty slice to clear them when there are
	// no secondary GIDs.  This prevents the target user from inheriting
	// any supplementary groups from the server process.
	if secondaryGIDs == nil {
		secondaryGIDs = []uint32{}
	}
	if err := threadSetgroups(secondaryGIDs); err != nil {
		var zero T
		return zero, fmt.Errorf("failed to set supplementary groups: %w", err)
	}

	// Set FS GID (while we still have root UID).
	//
	// setfsgid(2) always returns the previous fsgid regardless of
	// success/failure and does not reliably set errno.  To verify that
	// the change took effect, we call setfsgid again: if the returned
	// "previous" value is the GID we just requested, the first call
	// succeeded.
	prevGid, _, _ := syscall.Syscall(syscall.SYS_SETFSGID, uintptr(gid), 0, 0)
	checkGid, _, _ := syscall.Syscall(syscall.SYS_SETFSGID, uintptr(gid), 0, 0)
	if checkGid != uintptr(gid) {
		threadSetgroups(prevGroups) //nolint:errcheck
		var zero T
		return zero, fmt.Errorf("setfsgid(%d) failed: fsgid is still %d", gid, checkGid)
	}

	// Set FS UID.
	//
	// Same verification pattern as setfsgid above.
	prevUid, _, _ := syscall.Syscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0)
	checkUid, _, _ := syscall.Syscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0)
	if checkUid != uintptr(uid) {
		// Restore GID and groups before returning.  Panic on failure:
		// a thread with wrong credentials must not be returned to the pool.
		if _, _, e := syscall.Syscall(syscall.SYS_SETFSGID, uintptr(prevGid), 0, 0); e != 0 {
			panic(fmt.Sprintf("critical: failed to restore fsgid to %d: %v", prevGid, e))
		}
		if e := threadSetgroups(prevGroups); e != nil {
			panic(fmt.Sprintf("critical: failed to restore supplementary groups: %v", e))
		}
		var zero T
		return zero, fmt.Errorf("setfsuid(%d) failed: fsuid is still %d", uid, checkUid)
	}

	defer func() {
		// Restore UID first (regaining privileges), then GID, then groups.
		// Panic on failure: a thread with wrong credentials must not be
		// returned to the Go runtime's thread pool.
		//
		// Note: setfsuid/setfsgid do not reliably set errno; we verify
		// restoration by calling a second time and checking the returned
		// previous value.
		syscall.Syscall(syscall.SYS_SETFSUID, uintptr(prevUid), 0, 0) //nolint:errcheck
		if check, _, _ := syscall.Syscall(syscall.SYS_SETFSUID, uintptr(prevUid), 0, 0); check != uintptr(prevUid) {
			panic(fmt.Sprintf("critical: failed to restore fsuid to %d: current is %d", prevUid, check))
		}
		syscall.Syscall(syscall.SYS_SETFSGID, uintptr(prevGid), 0, 0) //nolint:errcheck
		if check, _, _ := syscall.Syscall(syscall.SYS_SETFSGID, uintptr(prevGid), 0, 0); check != uintptr(prevGid) {
			panic(fmt.Sprintf("critical: failed to restore fsgid to %d: current is %d", prevGid, check))
		}
		if e := threadSetgroups(prevGroups); e != nil {
			panic(fmt.Sprintf("critical: failed to restore supplementary groups: %v", e))
		}
	}()

	return fn()
}

// runAsUserNoReturn is a convenience wrapper for operations that return only an error.
func runAsUserNoReturn(uid, gid uint32, secondaryGIDs []uint32, fn func() error) error {
	_, err := runAsUser(uid, gid, secondaryGIDs, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

// --- webdav.FileSystem interface implementation ---

// Mkdir implements webdav.FileSystem.
func (m *multiuserFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	id, err := m.resolveIdentity(ctx)
	if err != nil {
		return err
	}
	err = runAsUserNoReturn(id.UID, id.GID, id.SecondaryGIDs, func() error {
		return m.inner.Mkdir(ctx, name, perm)
	})
	m.logOp("mkdir", name, id, err)
	return err
}

// OpenFile implements webdav.FileSystem.
func (m *multiuserFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	id, err := m.resolveIdentity(ctx)
	if err != nil {
		return nil, err
	}
	f, err := runAsUser(id.UID, id.GID, id.SecondaryGIDs, func() (webdav.File, error) {
		return m.inner.OpenFile(ctx, name, flag, perm)
	})
	m.logOp("open", name, id, err)
	return f, err
}

// RemoveAll implements webdav.FileSystem.
func (m *multiuserFileSystem) RemoveAll(ctx context.Context, name string) error {
	id, err := m.resolveIdentity(ctx)
	if err != nil {
		return err
	}
	err = runAsUserNoReturn(id.UID, id.GID, id.SecondaryGIDs, func() error {
		return m.inner.RemoveAll(ctx, name)
	})
	m.logOp("remove", name, id, err)
	return err
}

// Rename implements webdav.FileSystem.
func (m *multiuserFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	id, err := m.resolveIdentity(ctx)
	if err != nil {
		return err
	}
	err = runAsUserNoReturn(id.UID, id.GID, id.SecondaryGIDs, func() error {
		return m.inner.Rename(ctx, oldName, newName)
	})
	m.logOp("rename", oldName+"->"+newName, id, err)
	return err
}

// Stat implements webdav.FileSystem.
func (m *multiuserFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	id, err := m.resolveIdentity(ctx)
	if err != nil {
		return nil, err
	}
	fi, err := runAsUser(id.UID, id.GID, id.SecondaryGIDs, func() (os.FileInfo, error) {
		return m.inner.Stat(ctx, name)
	})
	m.logOp("stat", name, id, err)
	return fi, err
}
