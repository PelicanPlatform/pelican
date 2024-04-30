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

package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCachedOptions(t *testing.T) {
	// cached item returns without fetch
	t.Run("cached-item-returns-w/o-fetch", func(t *testing.T) {
		optionsCache.DeleteAll()
		optionsCache.Set("https://mock.com", []registrationFieldOption{{Name: "foo", ID: "bar"}}, ttlcache.DefaultTTL)
		got, err := getCachedOptions("https://mock.com", ttlcache.DefaultTTL)
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, "foo", got[0].Name)
		assert.Equal(t, "bar", got[0].ID)
		optionsCache.DeleteAll()
	})

	t.Run("new-item-with-empty-key", func(t *testing.T) {
		optionsCache.DeleteAll()
		_, err := getCachedOptions("", ttlcache.DefaultTTL)
		require.Error(t, err)
		assert.Equal(t, "key is empty", err.Error())
	})

	t.Run("new-item-with-bad-key", func(t *testing.T) {
		optionsCache.DeleteAll()
		_, err := getCachedOptions("this-is-not-url", ttlcache.DefaultTTL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to request the key")
	})

	t.Run("new-item-with-non-200-response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		optionsCache.DeleteAll()
		_, err := getCachedOptions(ts.URL, ttlcache.DefaultTTL)
		require.Error(t, err)
		assert.Equal(t, fmt.Sprintf("fetching key %s returns status code 500 with response body ", ts.URL), err.Error())
	})

	t.Run("new-item-with-wrong-struct", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			badResponse := `{}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(badResponse))
			require.NoError(t, err)
		}))
		defer ts.Close()

		optionsCache.DeleteAll()
		_, err := getCachedOptions(ts.URL, ttlcache.DefaultTTL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse response from key")
	})

	t.Run("new-item-with-empty-id", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			badResponse := `[{"name":"foo","rorid":"bar"}]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(badResponse))
			require.NoError(t, err)
		}))
		defer ts.Close()

		optionsCache.DeleteAll()
		_, err := getCachedOptions(ts.URL, ttlcache.DefaultTTL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "have empty ID for option")
	})

	t.Run("new-item-with-duplicated-ids", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			badResponse := `[{"name":"foo","id":"bar"}, {"name":"barz","id":"bar"}]`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(badResponse))
			require.NoError(t, err)
		}))
		defer ts.Close()

		optionsCache.DeleteAll()
		_, err := getCachedOptions(ts.URL, ttlcache.DefaultTTL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "are not unique")
	})

	t.Run("new-item-with-successful-fetch", func(t *testing.T) {
		mockOptions := []registrationFieldOption{
			{Name: "option A", ID: "optionA"},
			{Name: "option B", ID: "optionB"},
		}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			res, err := json.Marshal(mockOptions)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte(res))
			require.NoError(t, err)
		}))
		defer ts.Close()

		optionsCache.DeleteAll()
		options, err := getCachedOptions(ts.URL, ttlcache.DefaultTTL)
		require.NoError(t, err)
		assert.EqualValues(t, mockOptions, options)
	})
}

func TestConvertCustomRegFields(t *testing.T) {
	t.Run("options-overwrites-optionsURL", func(t *testing.T) {
		mockConfig := []customRegFieldsConfig{
			{
				Name: "mock1",
				Type: string(Enum),
				Options: []registrationFieldOption{
					{
						Name: "foo",
						ID:   "bar",
					},
				},
			},
			{
				Name: "mock1",
				Type: string(Enum),
				Options: []registrationFieldOption{
					{
						Name: "foo",
						ID:   "bar",
					},
				},
				OptionsUrl: "https://mock.com/url",
			},
		}

		regFields := convertCustomRegFields(mockConfig)
		require.Equal(t, 2, len(mockConfig))
		assert.Empty(t, regFields[0].OptionsUrl)
		assert.Empty(t, regFields[1].OptionsUrl)
		assert.Equal(t, 1, len(regFields[0].Options))
		assert.Equal(t, 1, len(regFields[1].Options))
	})

	t.Run("convert-names", func(t *testing.T) {
		mockConfig := []customRegFieldsConfig{
			{
				Name: "department_name",
			},
		}

		regField := convertCustomRegFields(mockConfig)
		require.Equal(t, 1, len(regField))
		assert.Equal(t, "Department Name", regField[0].DisplayedName)
		assert.Equal(t, "custom_fields.department_name", regField[0].Name)
	})
}
