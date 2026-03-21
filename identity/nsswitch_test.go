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

package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNSSwitch(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []NSSSwitchMethod
	}{
		{
			name:     "sss then files",
			content:  "passwd: sss files\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodSSS, NSSSwitchMethodFiles},
		},
		{
			name:     "files only",
			content:  "passwd: files\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles},
		},
		{
			name:     "sss only",
			content:  "passwd: sss\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodSSS},
		},
		{
			name:     "files then sss",
			content:  "passwd: files sss\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles, NSSSwitchMethodSSS},
		},
		{
			name:     "with unsupported methods",
			content:  "passwd: files ldap sss nis\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles, NSSSwitchMethodSSS},
		},
		{
			name:     "with systemd (ignored)",
			content:  "passwd: sss files systemd\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodSSS, NSSSwitchMethodFiles},
		},
		{
			name:     "with actions",
			content:  "passwd: files [NOTFOUND=return] sss\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles, NSSSwitchMethodSSS},
		},
		{
			name:     "no passwd line",
			content:  "group: files\nshadow: files\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles},
		},
		{
			name:     "empty file",
			content:  "",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "nsswitch.conf")
			err := os.WriteFile(tmpFile, []byte(tt.content), 0600)
			require.NoError(t, err)

			methods, err := ParseNSSwitch(tmpFile)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, methods)
		})
	}
}

func TestParseNSSwitch_MissingFile(t *testing.T) {
	_, err := ParseNSSwitch("/tmp/nonexistent-nsswitch-conf-12345")
	require.Error(t, err)
}

func TestParseNSSwitchRealFile(t *testing.T) {
	methods, err := ParseNSSwitch("/etc/nsswitch.conf")
	if err != nil {
		t.Logf("Cannot read /etc/nsswitch.conf (expected in some environments): %v", err)
		return
	}
	t.Logf("Real nsswitch.conf passwd methods: %v", methods)
	assert.NotEmpty(t, methods, "expected at least one method from real nsswitch.conf")
}
