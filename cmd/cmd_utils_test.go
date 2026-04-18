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

package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestResolveTokenOptions(t *testing.T) {
	newCmd := func(flags map[string]string) *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().StringP("token", "t", "", "")
		cmd.Flags().String("source-token", "", "")
		cmd.Flags().String("dest-token", "", "")
		for k, v := range flags {
			_ = cmd.Flags().Set(k, v)
		}
		return cmd
	}

	t.Run("NoFlags", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(nil))
		assert.Empty(t, opts)
	})

	t.Run("TokenOnly", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{"token": "/tmp/tok"}))
		assert.Len(t, opts, 1)
	})

	t.Run("SourceTokenOnly", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{"source-token": "/tmp/src"}))
		assert.Len(t, opts, 1)
	})

	t.Run("DestTokenOnly", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{"dest-token": "/tmp/dst"}))
		assert.Len(t, opts, 1)
	})

	t.Run("AllThreeFlags", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{
			"token":        "/tmp/tok",
			"source-token": "/tmp/src",
			"dest-token":   "/tmp/dst",
		}))
		// All three produce options; the specific overrides are resolved by the client library
		assert.Len(t, opts, 3)
	})

	t.Run("TokenAndSourceToken", func(t *testing.T) {
		opts := resolveTokenOptions(newCmd(map[string]string{
			"token":        "/tmp/tok",
			"source-token": "/tmp/src",
		}))
		assert.Len(t, opts, 2)
	})
}
