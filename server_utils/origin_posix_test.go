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

package server_utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/utils"

	"github.com/pelicanplatform/pelican/param"
)

func TestValidateAtomicUploadFilesystem(t *testing.T) {
	ResetTestState()

	t.Run("same-filesystem-passes", func(t *testing.T) {
		defer ResetTestState()

		tmpDir := t.TempDir()
		storageDir := filepath.Join(tmpDir, "storage")
		uploadDir := filepath.Join(tmpDir, "uploads")
		require.NoError(t, os.MkdirAll(storageDir, 0750))
		require.NoError(t, os.MkdirAll(uploadDir, 0750))

		require.NoError(t, param.Origin_EnableAtomicUploads.Set(true))
		require.NoError(t, param.Origin_UploadTempLocation.Set(uploadDir))

		o := &PosixOrigin{}
		e := &OriginExport{
			StoragePrefix:    storageDir,
			FederationPrefix: "/test",
		}
		err := o.validateAtomicUploadFilesystem(e)
		assert.NoError(t, err)
	})

	t.Run("cross-filesystem-fails", func(t *testing.T) {
		defer ResetTestState()

		// /dev/shm is typically a tmpfs mount, making it a different filesystem from /tmp
		if _, err := os.Stat("/dev/shm"); os.IsNotExist(err) {
			t.Skip("/dev/shm not available for cross-filesystem test")
		}

		tmpDir := t.TempDir() // on root filesystem
		storageDir := filepath.Join(tmpDir, "storage")
		require.NoError(t, os.MkdirAll(storageDir, 0750))

		// Verify they're actually on different filesystems before testing
		shmDir := filepath.Join("/dev/shm", "pelican-test-"+t.Name())
		require.NoError(t, os.MkdirAll(shmDir, 0750))
		t.Cleanup(func() { os.RemoveAll(shmDir) })

		same, err := utils.SameFilesystem(storageDir, shmDir)
		require.NoError(t, err)
		if same {
			t.Skip("/dev/shm is on the same filesystem as /tmp; cannot test cross-filesystem")
		}

		require.NoError(t, param.Origin_EnableAtomicUploads.Set(true))
		require.NoError(t, param.Origin_UploadTempLocation.Set(shmDir))

		o := &PosixOrigin{}
		e := &OriginExport{
			StoragePrefix:    storageDir,
			FederationPrefix: "/test",
		}
		err = o.validateAtomicUploadFilesystem(e)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "different filesystems")
		assert.Contains(t, err.Error(), "rename(2)")
	})

	t.Run("atomic-uploads-disabled-skips-check", func(t *testing.T) {
		defer ResetTestState()

		require.NoError(t, param.Origin_EnableAtomicUploads.Set(false))
		require.NoError(t, param.Origin_UploadTempLocation.Set("/some/nonexistent/path"))

		o := &PosixOrigin{}
		e := &OriginExport{
			StoragePrefix:    "/another/nonexistent/path",
			FederationPrefix: "/test",
		}
		err := o.validateAtomicUploadFilesystem(e)
		assert.NoError(t, err)
	})

	t.Run("empty-upload-temp-location-returns-error", func(t *testing.T) {
		defer ResetTestState()

		require.NoError(t, param.Origin_EnableAtomicUploads.Set(true))
		require.NoError(t, param.Origin_UploadTempLocation.Set(""))

		o := &PosixOrigin{}
		e := &OriginExport{
			StoragePrefix:    "/some/path",
			FederationPrefix: "/test",
		}
		err := o.validateAtomicUploadFilesystem(e)
		require.Error(t, err)
		assert.Contains(t, err.Error(), param.Origin_EnableAtomicUploads.GetName())
		assert.Contains(t, err.Error(), param.Origin_UploadTempLocation.GetName())
	})
}
