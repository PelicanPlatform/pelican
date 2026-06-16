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

func TestLoggingNamespaceSitename(t *testing.T) {
	t.Run("ValidPath", func(t *testing.T) {
		site, ok := LoggingNamespaceSitename("/pelican/logging/my-origin")
		assert.True(t, ok)
		assert.Equal(t, "my-origin", site)
	})

	t.Run("SitenameWithDots", func(t *testing.T) {
		site, ok := LoggingNamespaceSitename("/pelican/logging/uw-madison.edu")
		assert.True(t, ok)
		assert.Equal(t, "uw-madison.edu", site)
	})

	t.Run("PrefixOnly", func(t *testing.T) {
		_, ok := LoggingNamespaceSitename(LoggingNamespacePrefix)
		assert.False(t, ok)
	})

	t.Run("PrefixWithTrailingSlashOnly", func(t *testing.T) {
		_, ok := LoggingNamespaceSitename(LoggingNamespacePrefix + "/")
		assert.False(t, ok)
	})

	t.Run("UnrelatedPath", func(t *testing.T) {
		_, ok := LoggingNamespaceSitename("/origins/some.host")
		assert.False(t, ok)
	})

	t.Run("EmptyString", func(t *testing.T) {
		_, ok := LoggingNamespaceSitename("")
		assert.False(t, ok)
	})

	t.Run("MultipleSegments", func(t *testing.T) {
		// A crafted prefix like /pelican/logging/my-origin/subpath must not be
		// accepted — a valid logging namespace has exactly one path segment
		// after the prefix.
		_, ok := LoggingNamespaceSitename("/pelican/logging/my-origin/subpath")
		assert.False(t, ok)
	})
}

func TestLoggingNamespaceForServer(t *testing.T) {
	assert.Equal(t, "/pelican/logging/my-origin", LoggingNamespaceForServer("my-origin"))
	assert.Equal(t, "/pelican/logging/uw-madison-cache", LoggingNamespaceForServer("uw-madison-cache"))
}
