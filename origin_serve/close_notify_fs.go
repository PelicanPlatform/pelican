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

// File close_notify_fs.go provides a minimal "fire a callback on
// successful Close()" webdav.FileSystem wrapper. It exists for the
// configuration where metadata publishing is enabled but POSC is not:
// publishing still wants to be guarded by a successful close, but
// without the temp-file rename ceremony.
//
// Without POSC, a "successful close" is strictly weaker than with
// POSC — the file may have been observed by readers mid-stream — but
// the callback still fires only when Close() returns nil.

package origin_serve

import (
	"context"
	"os"
	"sync"

	"golang.org/x/net/webdav"
)

type closeNotifyFs struct {
	inner     webdav.FileSystem
	closeHook func(ctx context.Context, finalPath string, info os.FileInfo) error
}

func newCloseNotifyFs(inner webdav.FileSystem, hook func(ctx context.Context, finalPath string, info os.FileInfo) error) *closeNotifyFs {
	return &closeNotifyFs{inner: inner, closeHook: hook}
}

func (c *closeNotifyFs) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return c.inner.Mkdir(ctx, name, perm)
}

func (c *closeNotifyFs) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	f, err := c.inner.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	if flag&(os.O_CREATE|os.O_WRONLY|os.O_RDWR) == 0 {
		return f, nil
	}
	return &closeNotifyFile{File: f, fs: c, ctx: ctx, finalPath: name}, nil
}

func (c *closeNotifyFs) RemoveAll(ctx context.Context, name string) error {
	return c.inner.RemoveAll(ctx, name)
}

func (c *closeNotifyFs) Rename(ctx context.Context, oldName, newName string) error {
	return c.inner.Rename(ctx, oldName, newName)
}

func (c *closeNotifyFs) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	return c.inner.Stat(ctx, name)
}

type closeNotifyFile struct {
	webdav.File
	fs        *closeNotifyFs
	ctx       context.Context
	finalPath string
	mu        sync.Mutex
	closed    bool
}

func (cf *closeNotifyFile) Close() error {
	cf.mu.Lock()
	if cf.closed {
		cf.mu.Unlock()
		return nil
	}
	cf.closed = true
	cf.mu.Unlock()

	if err := cf.File.Close(); err != nil {
		return err
	}
	if cf.fs.closeHook != nil {
		info, _ := cf.fs.inner.Stat(cf.ctx, cf.finalPath)
		if err := cf.fs.closeHook(cf.ctx, cf.finalPath, info); err != nil {
			return err
		}
	}
	return nil
}

// Abort closes the underlying handle WITHOUT firing the close hook. Without
// POSC there is no staging file to discard — the bytes were written in place —
// so the caller is responsible for removing the (partial) object; the point of
// Abort is only to ensure a failed transfer does not publish a webhook or
// record a commit. Idempotent with Close.
func (cf *closeNotifyFile) Abort() error {
	cf.mu.Lock()
	if cf.closed {
		cf.mu.Unlock()
		return nil
	}
	cf.closed = true
	cf.mu.Unlock()
	return cf.File.Close()
}
