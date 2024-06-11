//go:build !windows

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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordMain(t *testing.T) {
	t.Run("w-password-arg", func(t *testing.T) {
		tmpWd := setupTestRun(t)
		tempDir := t.TempDir()
		inPasswordPath = filepath.Join(tempDir, "password-in")
		outPasswordPath = ""
		err := os.WriteFile(inPasswordPath, []byte("123456"), 0644)
		require.NoError(t, err)
		err = passwordMain(nil, []string{})
		require.NoError(t, err)

		_, err = os.Stat(filepath.Join(tmpWd, "server-web-passwd"))
		require.NoError(t, err)
	})

	t.Run("w-password-and-output-arg", func(t *testing.T) {
		tempDir := t.TempDir()
		inPasswordPath = filepath.Join(tempDir, "password-in")
		outPasswordPath = filepath.Join(tempDir, "test-passwd")

		err := os.WriteFile(inPasswordPath, []byte("123456"), 0644)
		require.NoError(t, err)
		err = passwordMain(nil, []string{})
		require.NoError(t, err)

		_, err = os.Stat(outPasswordPath)
		require.NoError(t, err)
	})
}
