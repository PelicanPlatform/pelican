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

package client_agent

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

func TestWalletSessionLockedByDefault(t *testing.T) {
	w := NewWalletSession()
	assert.False(t, w.IsOpen(), "a new wallet session should be locked")

	_, err := w.Contents()
	assert.ErrorIs(t, err, ErrWalletLocked, "reading a locked wallet should fail")
}

func TestWalletCloseIsIdempotent(t *testing.T) {
	w := NewWalletSession()
	w.Close()
	w.Close()
	assert.False(t, w.IsOpen())
}

func TestWalletOpenWithoutCredentialFile(t *testing.T) {
	// Point ConfigDir at an empty temp dir so no wallet file exists.
	viper.Reset()
	dir := t.TempDir()
	require.NoError(t, param.Set(param.ConfigDir, dir))
	t.Cleanup(func() {
		viper.Reset()
		config.ForgetPassword()
	})

	w := NewWalletSession()
	err := w.Open([]byte("irrelevant"))
	require.Error(t, err, "opening with no credential file should fail")
	assert.False(t, w.IsOpen())
}
