//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Morgridge Institute for Research
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

package client

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestDirectory(t *testing.T, path string) {
	subdirPath := filepath.Join(path, "subdir1")
	siblingPath := filepath.Join(path, "foo.txt")
	childPath := filepath.Join(path, "subdir1", "bar.txt")
	err := os.Mkdir(subdirPath, 0750)
	require.NoError(t, err)
	err = os.WriteFile(siblingPath, []byte("foo"), 0640)
	require.NoError(t, err)
	err = os.WriteFile(childPath, []byte("bar"), 0440)
	require.NoError(t, err)
}

func verifyTestDirectory(t *testing.T, testDirectory string) {
	entryCount := 0
	err := filepath.WalkDir(testDirectory, func(path string, dent fs.DirEntry, err error) error {
		// Skip the top-level directory itself.
		if len(testDirectory) >= len(path) {
			return nil
		}
		switch path[len(testDirectory)+1:] {
		case "subdir1":
			fi, err := dent.Info()
			require.NoError(t, err)
			assert.True(t, fi.Mode().IsDir())
			assert.Equal(t, fi.Mode()&fs.ModePerm, fs.FileMode(0750))
		case "foo.txt":
			fi, err := dent.Info()
			require.NoError(t, err)
			assert.True(t, fi.Mode().IsRegular())
			assert.Equal(t, fi.Mode()&fs.ModePerm, fs.FileMode(0640))
			buffer, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, string(buffer), "foo")
		case filepath.Join("subdir1", "bar.txt"):
			fi, err := dent.Info()
			require.NoError(t, err)
			assert.True(t, fi.Mode().IsRegular())
			assert.Equal(t, fi.Mode()&fs.ModePerm, fs.FileMode(0440))
			buffer, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, string(buffer), "bar")
		default:
			assert.Failf(t, "Unknown file encountered in directory", path)
		}
		entryCount += 1
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, entryCount, 3)
}

func verifyTarball(t *testing.T, reader io.Reader) {
	tr := tar.NewReader(reader)
	entryCount := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		entryCount += 1
		switch hdr.Name {
		case "subdir1":
			assert.Equal(t, hdr.Typeflag, uint8(tar.TypeDir))
			assert.Equal(t, hdr.Mode, int64(0750))
		case "foo.txt":
			assert.Equal(t, hdr.Typeflag, uint8(tar.TypeReg))
			assert.Equal(t, hdr.Mode, int64(0640))
			buffer := new(bytes.Buffer)
			_, err := io.Copy(buffer, tr)
			require.NoError(t, err)
			assert.Equal(t, buffer.String(), string([]byte("foo")))
		case filepath.Join("subdir1", "bar.txt"):
			assert.Equal(t, hdr.Typeflag, uint8(tar.TypeReg))
			assert.Equal(t, hdr.Mode, int64(0440))
			buffer := new(bytes.Buffer)
			_, err := io.Copy(buffer, tr)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(buffer.Bytes(), []byte("bar")))
		default:
			assert.Failf(t, "Unknown file encountered in tarball", hdr.Name)
		}
	}
	assert.Equal(t, entryCount, 3)
}

func TestAutoPacker(t *testing.T) {
	t.Parallel()

	t.Run("create-tarfile", func(t *testing.T) {
		dirname := t.TempDir()

		createTestDirectory(t, dirname)
		ap := newAutoPacker(dirname, tarBehavior)
		verifyTarball(t, ap)

		// Unwrap the GZIP stream, pass to the tarball verifier
		ap = newAutoPacker(dirname, tarGZBehavior)
		gzReader, err := gzip.NewReader(ap)
		require.NoError(t, err)
		verifyTarball(t, gzReader)

		// Default behavior should be the same as the tar.gz
		ap = newAutoPacker(dirname, autoBehavior)
		gzReader, err = gzip.NewReader(ap)
		require.NoError(t, err)
		verifyTarball(t, gzReader)
	})

	t.Run("unpack-tarfile", func(t *testing.T) {
		dirnameSource := t.TempDir()
		dirnameDest := t.TempDir()

		createTestDirectory(t, dirnameSource)
		ap := newAutoPacker(dirnameSource, tarGZBehavior)

		aup := newAutoUnpacker(dirnameDest, autoBehavior)
		_, err := io.Copy(aup, ap)
		require.NoError(t, err)

		require.NoError(t, aup.Error())
		require.NoError(t, aup.Close())
		verifyTestDirectory(t, dirnameDest)
	})
}

// tarEntry describes one archive member for buildTar.
type tarEntry struct {
	Name     string
	Typeflag byte
	Linkname string
	Mode     int64
	Body     string
}

// buildTar writes the given entries into an in-memory (uncompressed) tar
// archive.  Regular files default to mode 0644 and directories to 0755.
func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	for _, e := range entries {
		mode := e.Mode
		if mode == 0 {
			if e.Typeflag == tar.TypeDir {
				mode = 0755
			} else {
				mode = 0644
			}
		}
		hdr := &tar.Header{
			Name:     e.Name,
			Typeflag: e.Typeflag,
			Linkname: e.Linkname,
			Mode:     mode,
		}
		if e.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.Body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if e.Typeflag == tar.TypeReg {
			_, err := io.WriteString(tw, e.Body)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// unpackBytes streams archive into a fresh unpacker rooted at dest and then
// closes it, returning the first error from either step.
func unpackBytes(dest string, archive []byte) error {
	aup := newAutoUnpacker(dest, autoBehavior)
	_, copyErr := io.Copy(aup, bytes.NewReader(archive))
	closeErr := aup.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// dirNames returns the sorted base names of the entries directly under dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSanitizeTarName(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]string{
		"a/b":     "a/b",
		"/a/b":    "a/b",
		"//a//b/": "a/b",
		"./a":     "a",
		"a/../b":  "b",
		"a/..":    ".",
		"":        ".",
		"/":       ".",
		"..a/b":   "..a/b",
	} {
		got, err := sanitizeTarName(name)
		require.NoError(t, err, "name %q", name)
		assert.Equal(t, want, got, "name %q", name)
	}

	for _, name := range []string{"..", "../x", "/../x", "//..//x", "/./../x", "a/../../x", "../"} {
		_, err := sanitizeTarName(name)
		assert.Error(t, err, "name %q must be rejected", name)
	}
}

// TestAutoUnpackerRejectsEscapes covers the ways an archive can try to write
// outside the destination directory: `..` components, a sibling directory
// sharing the destination's name as a prefix, and writing through a symlink
// whose target lies outside the destination.
func TestAutoUnpackerRejectsEscapes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		entries func(dest, outside string) []tarEntry
		// preSeed runs after dest/outside are created and before unpacking.
		preSeed func(t *testing.T, dest, outside string)
		// extraCheck runs after the unpack failure for case-specific assertions.
		extraCheck func(t *testing.T, parent, dest, outside string)
	}

	relOutside := func(dest, outside string) string {
		rel, err := filepath.Rel(dest, outside)
		require.NoError(t, err)
		return rel
	}

	cases := []testCase{
		{
			name: "dot-dot regular file",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{{Name: "../escape.txt", Typeflag: tar.TypeReg, Body: "pwned"}}
			},
		},
		{
			// "/../x" must be refused, not collapsed to "x" inside the destination.
			name: "absolute dot-dot regular file",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{{Name: "/../escape.txt", Typeflag: tar.TypeReg, Body: "pwned"}}
			},
			extraCheck: func(t *testing.T, parent, dest, outside string) {
				_, err := os.Lstat(filepath.Join(dest, "escape.txt"))
				assert.True(t, os.IsNotExist(err), "entry must not be silently renamed into the destination")
			},
		},
		{
			// destDir=/parent/dest; entry ../dest-evil/x joins to /parent/dest-evil/x,
			// which passes a bare string-prefix check against /parent/dest.
			name: "sibling prefix bypass",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{
					{Name: "../" + filepath.Base(dest) + "-evil", Typeflag: tar.TypeDir},
					{Name: "../" + filepath.Base(dest) + "-evil/x", Typeflag: tar.TypeReg, Body: "pwned"},
				}
			},
			extraCheck: func(t *testing.T, parent, dest, outside string) {
				_, err := os.Lstat(dest + "-evil")
				assert.True(t, os.IsNotExist(err), "sibling directory must not be created")
			},
		},
		{
			name: "absolute symlink then file through it",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{
					{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: outside},
					{Name: "evil/pwned", Typeflag: tar.TypeReg, Body: "pwned"},
				}
			},
		},
		{
			name: "relative symlink then file through it",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{
					{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: relOutside(dest, outside)},
					{Name: "evil/pwned", Typeflag: tar.TypeReg, Body: "pwned"},
				}
			},
		},
		{
			name: "symlink then directory through it",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{
					{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: outside},
					{Name: "evil/sub", Typeflag: tar.TypeDir},
				}
			},
			extraCheck: func(t *testing.T, parent, dest, outside string) {
				_, err := os.Lstat(filepath.Join(outside, "sub"))
				assert.True(t, os.IsNotExist(err), "directory must not be created through the symlink")
			},
		},
		{
			name: "symlink then hard link through it",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{
					{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: outside},
					{Name: "h", Typeflag: tar.TypeLink, Linkname: "evil/target"},
				}
			},
			extraCheck: func(t *testing.T, parent, dest, outside string) {
				_, err := os.Lstat(filepath.Join(dest, "h"))
				assert.True(t, os.IsNotExist(err), "hard link to an outside file must not be created")
			},
		},
		{
			name: "dot-dot hard link target",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{
					{Name: "h", Typeflag: tar.TypeLink, Linkname: "../" + filepath.Base(outside) + "/target"},
				}
			},
			extraCheck: func(t *testing.T, parent, dest, outside string) {
				_, err := os.Lstat(filepath.Join(dest, "h"))
				assert.True(t, os.IsNotExist(err), "hard link to an outside file must not be created")
			},
		},
		{
			name: "absolute dot-dot hard link target",
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{
					{Name: "h", Typeflag: tar.TypeLink, Linkname: "/../" + filepath.Base(outside) + "/target"},
				}
			},
			extraCheck: func(t *testing.T, parent, dest, outside string) {
				_, err := os.Lstat(filepath.Join(dest, "h"))
				assert.True(t, os.IsNotExist(err), "hard link to an outside file must not be created")
			},
		},
		{
			// The archive is clean; the user's destination already holds a
			// symlink pointing outside.  It must not be followed either.
			name: "pre-existing symlink in destination",
			preSeed: func(t *testing.T, dest, outside string) {
				require.NoError(t, os.Symlink(outside, filepath.Join(dest, "pre")))
			},
			entries: func(dest, outside string) []tarEntry {
				return []tarEntry{{Name: "pre/x", Typeflag: tar.TypeReg, Body: "pwned"}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			outside := filepath.Join(parent, "outside")
			require.NoError(t, os.Mkdir(dest, 0755))
			require.NoError(t, os.Mkdir(outside, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(outside, "target"), []byte("canary"), 0644))
			if tc.preSeed != nil {
				tc.preSeed(t, dest, outside)
			}

			err := unpackBytes(dest, buildTar(t, tc.entries(dest, outside)))
			require.Error(t, err)
			t.Logf("unpack refused: %v", err)

			// The canary directory must be untouched: exactly one entry, unchanged.
			assert.Equal(t, []string{"target"}, dirNames(t, outside))
			body, readErr := os.ReadFile(filepath.Join(outside, "target"))
			require.NoError(t, readErr)
			assert.Equal(t, "canary", string(body))
			// Nothing may have been written beside dest/outside in the parent either.
			assert.Equal(t, []string{"dest", "outside"}, dirNames(t, parent))

			if tc.extraCheck != nil {
				tc.extraCheck(t, parent, dest, outside)
			}
		})
	}
}

// TestAutoUnpackerAccepts pins the legitimate behaviours that the hardening
// must not break.
func TestAutoUnpackerAccepts(t *testing.T) {
	t.Parallel()

	t.Run("symlink with absolute target is created verbatim", func(t *testing.T) {
		t.Parallel()
		dest := t.TempDir()
		// Dangling and pointing outside: allowed, because nothing is written
		// through it.  Pelican's own packer records such targets verbatim.
		err := unpackBytes(dest, buildTar(t, []tarEntry{
			{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/nonexistent/elsewhere"},
		}))
		require.NoError(t, err)
		target, err := os.Readlink(filepath.Join(dest, "link"))
		require.NoError(t, err)
		assert.Equal(t, "/nonexistent/elsewhere", target)
	})

	t.Run("leading slash is stripped", func(t *testing.T) {
		t.Parallel()
		dest := t.TempDir()
		err := unpackBytes(dest, buildTar(t, []tarEntry{
			{Name: "/a", Typeflag: tar.TypeDir},
			{Name: "/a/b.txt", Typeflag: tar.TypeReg, Body: "b"},
		}))
		require.NoError(t, err)
		body, err := os.ReadFile(filepath.Join(dest, "a", "b.txt"))
		require.NoError(t, err)
		assert.Equal(t, "b", string(body))
	})

	t.Run("hard link inside destination", func(t *testing.T) {
		t.Parallel()
		dest := t.TempDir()
		err := unpackBytes(dest, buildTar(t, []tarEntry{
			{Name: "orig", Typeflag: tar.TypeReg, Body: "orig"},
			{Name: "copy", Typeflag: tar.TypeLink, Linkname: "orig"},
		}))
		require.NoError(t, err)
		body, err := os.ReadFile(filepath.Join(dest, "copy"))
		require.NoError(t, err)
		assert.Equal(t, "orig", string(body))
	})

	t.Run("overwrite truncates", func(t *testing.T) {
		t.Parallel()
		dest := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dest, "f.txt"), []byte("a much longer original body"), 0644))
		err := unpackBytes(dest, buildTar(t, []tarEntry{
			{Name: "f.txt", Typeflag: tar.TypeReg, Body: "short"},
		}))
		require.NoError(t, err)
		body, err := os.ReadFile(filepath.Join(dest, "f.txt"))
		require.NoError(t, err)
		assert.Equal(t, "short", string(body))
	})

	t.Run("setuid bit is dropped", func(t *testing.T) {
		t.Parallel()
		dest := t.TempDir()
		err := unpackBytes(dest, buildTar(t, []tarEntry{
			{Name: "bin", Typeflag: tar.TypeReg, Body: "#!/bin/sh\n", Mode: 0o4755},
		}))
		require.NoError(t, err)
		fi, err := os.Stat(filepath.Join(dest, "bin"))
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
		assert.Zero(t, fi.Mode()&fs.ModeSetuid)
	})

	t.Run("close without bytes is an error", func(t *testing.T) {
		t.Parallel()
		aup := newAutoUnpacker(t.TempDir(), autoBehavior)
		err := aup.Close()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "closed prior to any bytes written")
	})

	t.Run("missing destination directory", func(t *testing.T) {
		t.Parallel()
		aup := newAutoUnpacker(filepath.Join(t.TempDir(), "does-not-exist"), autoBehavior)
		require.Error(t, aup.Error())
	})
}
