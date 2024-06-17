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
	"bytes"
	"context"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestResetPassword(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	config.InitConfig()
	viper.Set("Server.WebPort", 8444)
	viper.Set("Origin.Port", 8443)
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)

	rootCmd.SetArgs([]string{"origin", "web-ui", "reset-password", "--stdin"})
	byteBuffer := bytes.NewReader([]byte("1234"))
	rootCmd.SetIn(byteBuffer)
	err = rootCmd.Execute()
	require.NoError(t, err)

	fileName := param.Server_UIPasswordFile.GetString()
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
