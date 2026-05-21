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

package server_structs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsLoggingNamespace(t *testing.T) {
	t.Run("NilCustomFields", func(t *testing.T) {
		reg := &Registration{}
		assert.False(t, reg.IsLoggingNamespace())
	})

	t.Run("EmptyCustomFields", func(t *testing.T) {
		reg := &Registration{CustomFields: map[string]interface{}{}}
		assert.False(t, reg.IsLoggingNamespace())
	})

	t.Run("WrongTypeValue", func(t *testing.T) {
		reg := &Registration{CustomFields: map[string]interface{}{RegistrationTypeKey: "data"}}
		assert.False(t, reg.IsLoggingNamespace())
	})

	t.Run("NonStringTypeValue", func(t *testing.T) {
		reg := &Registration{CustomFields: map[string]interface{}{RegistrationTypeKey: 42}}
		assert.False(t, reg.IsLoggingNamespace())
	})

	t.Run("LoggingTypeValue", func(t *testing.T) {
		reg := &Registration{CustomFields: map[string]interface{}{RegistrationTypeKey: LoggingRegistrationType}}
		assert.True(t, reg.IsLoggingNamespace())
	})
}

func TestLoggingNamespaceServerID(t *testing.T) {
	t.Run("ValidPath", func(t *testing.T) {
		id, ok := LoggingNamespaceServerID("/pelican/logging/abc1234")
		assert.True(t, ok)
		assert.Equal(t, "abc1234", id)
	})

	t.Run("PrefixOnly", func(t *testing.T) {
		_, ok := LoggingNamespaceServerID(LoggingNamespacePrefix)
		assert.False(t, ok)
	})

	t.Run("PrefixWithTrailingSlashOnly", func(t *testing.T) {
		_, ok := LoggingNamespaceServerID(LoggingNamespacePrefix + "/")
		assert.False(t, ok)
	})

	t.Run("UnrelatedPath", func(t *testing.T) {
		_, ok := LoggingNamespaceServerID("/origins/some.host")
		assert.False(t, ok)
	})

	t.Run("EmptyString", func(t *testing.T) {
		_, ok := LoggingNamespaceServerID("")
		assert.False(t, ok)
	})
}

func TestLoggingNamespaceForServer(t *testing.T) {
	assert.Equal(t, "/pelican/logging/abc1234", LoggingNamespaceForServer("abc1234"))
}
