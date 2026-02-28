//go:build !windows

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

package local_cache_test

import (
	"context"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestSpecialCharsOrigin tests that the origin can serve objects whose names
// contain characters that are problematic for URL encoding and XRootD.
// Each sub-test creates a file with a special character in the name,
// then downloads it via the transfer engine to verify end-to-end handling.
func TestSpecialCharsOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled {
			require.NoError(t, err)
		}
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		server_utils.ResetTestState()
	})

	// Use the local cache so the transfer engine can route correctly
	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	content := "Hello, Special Characters!"

	tests := []struct {
		name     string
		filename string
	}{
		{"Space", "file with spaces.txt"},
		{"PlusSign", "file+plus.txt"},
		{"Parentheses", "file(parens).txt"},
		{"SquareBrackets", "file[brackets].txt"},
		{"AtSign", "file@at.txt"},
		{"Ampersand", "file&amp.txt"},
		{"Equals", "file=equals.txt"},
		{"Comma", "file,comma.txt"},
		{"Semicolon", "file;semi.txt"},
		{"SingleQuote", "file'quote.txt"},
		{"Exclamation", "file!bang.txt"},
		{"Tilde", "file~tilde.txt"},
		{"MultipleSpaces", "path with multiple spaces.txt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Write the file to the origin's storage directory
			originPath := filepath.Join(ft.Exports[0].StoragePrefix, tc.filename)
			err := os.WriteFile(originPath, []byte(content), 0644)
			require.NoError(t, err, "failed to create test file on origin: %s", tc.filename)

			// Build the pelican URL with proper encoding
			downloadUrl := "pelican://" + param.Server_Hostname.GetString() + ":" +
				strconv.Itoa(param.Server_WebPort.GetInt()) +
				"/test/" + url.PathEscape(tc.filename)

			tmpDir := t.TempDir()
			destPath := filepath.Join(tmpDir, "output.txt")

			tr, err := client.DoGet(ctx, downloadUrl, destPath, false,
				client.WithCaches(cacheUrl))
			require.NoError(t, err, "DoGet failed for filename: %s", tc.filename)
			require.Equal(t, 1, len(tr), "expected exactly 1 transfer result")
			assert.NoError(t, tr[0].Error, "transfer error for filename: %s", tc.filename)
			assert.Equal(t, int64(len(content)), tr[0].TransferredBytes,
				"transferred bytes mismatch for filename: %s", tc.filename)

			// Verify the content
			readBack, err := os.ReadFile(destPath)
			require.NoError(t, err, "failed to read back downloaded file")
			assert.Equal(t, content, string(readBack),
				"content mismatch for filename: %s", tc.filename)
		})
	}
}

// TestSpecialCharsCache tests that the persistent cache correctly handles
// objects with special characters in their names.
// First retrieval is a cache miss (downloads from origin); second is a cache hit.
func TestSpecialCharsCache(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	content := "Hello, Special Characters!"

	tests := []struct {
		name     string
		filename string
	}{
		{"Space", "file with spaces.txt"},
		{"PlusSign", "file+plus.txt"},
		{"Parentheses", "file(parens).txt"},
		{"SquareBrackets", "file[brackets].txt"},
		{"AtSign", "file@at.txt"},
		{"Ampersand", "file&amp.txt"},
		{"Comma", "file,comma.txt"},
		{"SingleQuote", "file'quote.txt"},
		{"Tilde", "file~tilde.txt"},
		{"MultipleSpaces", "path with multiple spaces.txt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Write the file to the origin's storage directory
			originPath := filepath.Join(ft.Exports[0].StoragePrefix, tc.filename)
			err := os.WriteFile(originPath, []byte(content), 0644)
			require.NoError(t, err, "failed to create test file on origin: %s", tc.filename)

			objectPath := "/test/" + tc.filename

			// First retrieval — cache miss, downloads from origin
			reader, err := pc.Get(context.Background(), objectPath, "")
			require.NoError(t, err, "cache GET (miss) failed for: %s", tc.filename)
			byteBuff, err := io.ReadAll(reader)
			assert.NoError(t, err, "ReadAll failed for: %s", tc.filename)
			assert.Equal(t, content, string(byteBuff),
				"content mismatch on miss for: %s", tc.filename)
			reader.Close()

			// Second retrieval — cache hit
			reader, err = pc.Get(context.Background(), objectPath, "")
			require.NoError(t, err, "cache GET (hit) failed for: %s", tc.filename)
			byteBuff, err = io.ReadAll(reader)
			assert.NoError(t, err, "ReadAll failed on hit for: %s", tc.filename)
			assert.Equal(t, content, string(byteBuff),
				"content mismatch on hit for: %s", tc.filename)
			reader.Close()
		})
	}
}
