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

package web_ui

import (
	"os"
	"path"
	"testing"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"
)

func TestDoReload(t *testing.T) {
	server_utils.Reset()
	savedAuthDB := authDB.Load()
	authDB.Store(nil)
	defer authDB.Store(savedAuthDB)

	tempDir := t.TempDir()
	passwordFile := path.Join(tempDir, "/authdb")
	viper.Set("Server.UIPasswordFile", passwordFile)
	hook := test.NewGlobal()

	// Without a authdb set up, it should return nil with log message
	err := doReload()
	require.NoError(t, err)
	assert.Equal(t, 1, len(hook.Entries))
	assert.Equal(t, logrus.DebugLevel, hook.Entries[0].Level)
	assert.Equal(t, "Cannot reload auth database - not configured", hook.Entries[0].Message)

	// Set up a temp password file and assign to authDB
	file, err := os.OpenFile(passwordFile, os.O_WRONLY|os.O_CREATE, 0600)
	require.NoError(t, err)
	defer file.Close()
	content := "admin:password\n"
	_, err = file.WriteString(content)
	require.NoError(t, err, "error writing password to the temp password file")

	auth, err := htpasswd.New(passwordFile, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	require.NoError(t, err)

	authDB.Store(auth)

	// End of setup

	// With an authDB, no error should return with a reload call
	hook.Reset()
	err = doReload()
	require.NoError(t, err)
	assert.Equal(t, 1, len(hook.Entries))
	assert.Equal(t, logrus.DebugLevel, hook.Entries[0].Level)
	assert.Equal(t, "Successfully reloaded the auth database", hook.Entries[0].Message)

	// Change file mod to read only
	err = os.Chmod(passwordFile, 0400)
	require.NoError(t, err, "error chmod the temp password file")

	hook.Reset()
	err = doReload()
	require.NoError(t, err)
	assert.Equal(t, 1, len(hook.Entries))
	assert.Equal(t, logrus.DebugLevel, hook.Entries[0].Level)
	// Should be no error reload the auth db with read-only access
	assert.Equal(t, "Successfully reloaded the auth database", hook.Entries[0].Message)

}
