//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"testing"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"
)

func TestResetPassword(t *testing.T) {
	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	err := config.InitServer()
	require.NoError(t, err)

	rootCmd.SetArgs([]string{"origin", "web-ui", "reset-password", "--stdin"})
	byteBuffer := bytes.NewReader([]byte("1234"))
	rootCmd.SetIn(byteBuffer)
	err = rootCmd.Execute()
	require.NoError(t, err)

	fileName := param.Origin_UIPasswordFile.GetString()
	auth, err := htpasswd.New(fileName, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	require.NoError(t, err)

	assert.True(t, auth.Match("admin", "1234"))

	err = originUiResetCmd.Execute()
	require.NoError(t, err)
	byteBuffer = bytes.NewReader([]byte("5678"))
	originUiResetCmd.SetIn(byteBuffer)
	err = originUiResetCmd.Execute()
	require.NoError(t, err)

	err = auth.Reload(nil)
	require.NoError(t, err)

	assert.True(t, auth.Match("admin", "5678"))

	originUiResetCmd.SetArgs([]string{"origin", "web-ui", "reset-password", "--user", "testu"})
	byteBuffer = bytes.NewReader([]byte("abcd"))
	originUiResetCmd.SetIn(byteBuffer)
	err = originUiResetCmd.Execute()
	require.NoError(t, err)

	err = auth.Reload(nil)
	require.NoError(t, err)

	assert.True(t, auth.Match("admin", "abcd"))
}
