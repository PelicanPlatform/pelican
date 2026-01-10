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

package origin_serve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMapfileRuleMatching tests mapfile rule matching logic
func TestMapfileRuleMatching(t *testing.T) {
	testPath := filepath.Join(t.TempDir(), "mapfile.json")

	rules := []MapfileRule{
		{
			Sub:    strPtr("user1"),
			Result: "localuser1",
		},
		{
			Username: strPtr("user2"),
			Path:     strPtr("/home"),
			Result:   "homeuser2",
		},
		{
			Group:  strPtr("/cms/prod"),
			Result: "cmsprod",
		},
		{
			Group:  strPtr("/cms"),
			Path:   strPtr("/cms"),
			Result: "cmsuser",
		},
		{
			Username: strPtr("testuser"),
			Ignore:   boolPtr(true),
			Result:   "should_be_ignored",
		},
	}

	data, err := json.Marshal(rules)
	require.NoError(t, err)

	err = os.WriteFile(testPath, data, 0644)
	require.NoError(t, err)

	mapfile := NewMapfile(testPath)
	err = mapfile.Load()
	require.NoError(t, err)

	tests := []struct {
		name         string
		user         string
		groups       []string
		requestPath  string
		expectedUser string
		description  string
	}{
		{
			name:         "Match by sub claim",
			user:         "user1",
			groups:       []string{},
			requestPath:  "/any/path",
			expectedUser: "localuser1",
			description:  "Should match sub claim exactly",
		},
		{
			name:         "Match by username and path",
			user:         "user2",
			groups:       []string{},
			requestPath:  "/home/user2/data",
			expectedUser: "homeuser2",
			description:  "Should match both username and path prefix",
		},
		{
			name:         "No match for different username",
			user:         "user2",
			groups:       []string{},
			requestPath:  "/data/other",
			expectedUser: "",
			description:  "Path doesn't match /home",
		},
		{
			name:         "Match by group only",
			user:         "anyone",
			groups:       []string{"/cms/prod"},
			requestPath:  "/any/path",
			expectedUser: "cmsprod",
			description:  "Should match first matching group rule",
		},
		{
			name:         "Match by group and path",
			user:         "anyone",
			groups:       []string{"/cms"},
			requestPath:  "/cms/data",
			expectedUser: "cmsuser",
			description:  "Should match both group and path",
		},
		{
			name:         "Ignore flag prevents match",
			user:         "testuser",
			groups:       []string{},
			requestPath:  "/any/path",
			expectedUser: "",
			description:  "Rules with ignore=true should be skipped",
		},
		{
			name:         "No rules match",
			user:         "unknown",
			groups:       []string{},
			requestPath:  "/unknown/path",
			expectedUser: "",
			description:  "Should return empty string when no rules match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapfile.MapUsername(tt.user, tt.groups, tt.requestPath)
			assert.Equal(t, tt.expectedUser, result, tt.description)
		})
	}
}

// TestMapfileStaleness tests mapfile staleness detection
func TestMapfileStaleness(t *testing.T) {
	testPath := filepath.Join(t.TempDir(), "mapfile.json")

	rules := []MapfileRule{
		{
			Sub:    strPtr("user1"),
			Result: "localuser1",
		},
	}

	data, err := json.Marshal(rules)
	require.NoError(t, err)

	err = os.WriteFile(testPath, data, 0644)
	require.NoError(t, err)

	mapfile := NewMapfile(testPath)
	err = mapfile.Load()
	require.NoError(t, err)

	// Should not be stale immediately after load
	assert.False(t, mapfile.IsStale(), "Mapfile should not be stale immediately after load")

	// Wait a bit and modify the file
	time.Sleep(100 * time.Millisecond)
	newRules := []MapfileRule{
		{
			Sub:    strPtr("user2"),
			Result: "localuser2",
		},
	}
	newData, err := json.Marshal(newRules)
	require.NoError(t, err)

	err = os.WriteFile(testPath, newData, 0644)
	require.NoError(t, err)

	// Now it should be stale
	assert.True(t, mapfile.IsStale(), "Mapfile should be stale after modification")

	// Reload and verify it's not stale
	err = mapfile.Load()
	require.NoError(t, err)
	assert.False(t, mapfile.IsStale(), "Mapfile should not be stale after reload")
}

// TestUserMapperExtraction tests user info extraction
func TestUserMapperExtraction(t *testing.T) {
	tests := []struct {
		name          string
		usernameClaim string
		groupsClaim   string
		claims        map[string]interface{}
		expectedUser  string
		expectedGrps  []string
		description   string
	}{
		{
			name:          "ExtractSubjectAsUser",
			usernameClaim: "sub",
			groupsClaim:   "wlcg.groups",
			claims: map[string]interface{}{
				"sub": "user123",
				"wlcg.groups": []interface{}{
					"group1",
					"group2",
				},
			},
			expectedUser: "user123",
			expectedGrps: []string{"group1", "group2"},
			description:  "Should extract sub as username and wlcg.groups",
		},
		{
			name:          "DefaultToNobody",
			usernameClaim: "sub",
			groupsClaim:   "wlcg.groups",
			claims: map[string]interface{}{
				"iss": "https://example.com",
			},
			expectedUser: "nobody",
			expectedGrps: []string{},
			description:  "Should default to nobody when claims missing",
		},
		{
			name:          "ExtractCustomUsernameClaim",
			usernameClaim: "uid",
			groupsClaim:   "groups",
			claims: map[string]interface{}{
				"uid":    "customuser",
				"sub":    "ignored",
				"groups": []interface{}{"group3"},
			},
			expectedUser: "customuser",
			expectedGrps: []string{"group3"},
			description:  "Should extract uid not sub when configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := NewUserMapper(tt.usernameClaim, tt.groupsClaim, "")
			result := mapper.ExtractUserInfo(tt.claims, "/test/path")
			assert.Equal(t, tt.expectedUser, result.User)
			assert.Equal(t, tt.expectedGrps, result.Groups, tt.description)
		})
	}
}

// TestUserMapperWithMapfile tests user mapper with mapfile
func TestUserMapperWithMapfile(t *testing.T) {
	testPath := filepath.Join(t.TempDir(), "mapfile.json")

	rules := []MapfileRule{
		{
			Sub:    strPtr("bbockelm"),
			Path:   strPtr("/home"),
			Result: "bbockelm",
		},
		{
			Group:  strPtr("/cms/prod"),
			Result: "cmsprod",
		},
	}

	data, err := json.Marshal(rules)
	require.NoError(t, err)

	err = os.WriteFile(testPath, data, 0644)
	require.NoError(t, err)

	mapper := NewUserMapper("sub", "wlcg.groups", testPath)

	claims := map[string]interface{}{
		"sub": "bbockelm",
		"wlcg.groups": []interface{}{
			"/cms/prod",
		},
	}

	result := mapper.ExtractUserInfo(claims, "/home/bbockelm/data")
	assert.Equal(t, "bbockelm", result.User)
	assert.Equal(t, "bbockelm", result.MappedUser, "Should apply mapfile mapping")
	assert.Equal(t, []string{"/cms/prod"}, result.Groups)
}

// TestMapfileLoadErrors tests error handling for mapfile operations
func TestMapfileLoadErrors(t *testing.T) {
	t.Run("NonexistentFile", func(t *testing.T) {
		mapfile := NewMapfile("/nonexistent/path/mapfile.json")
		err := mapfile.Load()
		assert.Error(t, err, "Should fail to load nonexistent file")
		assert.Contains(t, err.Error(), "failed to read mapfile", "Should indicate read failure")
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		testPath := filepath.Join(t.TempDir(), "invalid.json")
		err := os.WriteFile(testPath, []byte("{ invalid json }"), 0644)
		require.NoError(t, err)

		mapfile := NewMapfile(testPath)
		err = mapfile.Load()
		assert.Error(t, err, "Should fail to parse invalid JSON")
		assert.Contains(t, err.Error(), "failed to parse mapfile JSON", "Should indicate JSON parse error")
	})

	t.Run("EmptyRulesArray", func(t *testing.T) {
		testPath := filepath.Join(t.TempDir(), "empty.json")
		data, _ := json.Marshal([]MapfileRule{})
		err := os.WriteFile(testPath, data, 0644)
		require.NoError(t, err)

		mapfile := NewMapfile(testPath)
		err = mapfile.Load()
		assert.NoError(t, err, "Should load empty rules successfully")
		assert.Equal(t, 0, len(mapfile.Rules))
	})
}

// TestUserMapperRefresh tests mapfile refresh functionality
func TestUserMapperRefresh(t *testing.T) {
	testPath := filepath.Join(t.TempDir(), "mapfile.json")

	rules := []MapfileRule{
		{
			Sub:    strPtr("user1"),
			Result: "mapped1",
		},
	}

	data, err := json.Marshal(rules)
	require.NoError(t, err)
	err = os.WriteFile(testPath, data, 0644)
	require.NoError(t, err)

	mapper := NewUserMapper("sub", "wlcg.groups", testPath)

	// Verify initial mapping works
	claims := map[string]interface{}{"sub": "user1"}
	result := mapper.ExtractUserInfo(claims, "/path")
	assert.Equal(t, "mapped1", result.MappedUser)

	// Wait and update mapfile
	time.Sleep(100 * time.Millisecond)
	newRules := []MapfileRule{
		{
			Sub:    strPtr("user1"),
			Result: "mapped_updated",
		},
	}
	newData, _ := json.Marshal(newRules)
	err = os.WriteFile(testPath, newData, 0644)
	require.NoError(t, err)

	// Refresh should pick up new mapping
	err = mapper.RefreshMapfile()
	require.NoError(t, err)

	result = mapper.ExtractUserInfo(claims, "/path")
	assert.Equal(t, "mapped_updated", result.MappedUser)
}

// Helper functions
func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

// BenchmarkMapfileMatching benchmarks mapfile rule matching
func BenchmarkMapfileMatching(b *testing.B) {
	testPath := filepath.Join(b.TempDir(), "mapfile.json")

	// Create a mapfile with many rules
	var rules []MapfileRule
	for i := 0; i < 100; i++ {
		group := "/group" + string(rune(i))
		rules = append(rules, MapfileRule{
			Group:  &group,
			Result: "user" + string(rune(i)),
		})
	}

	data, _ := json.Marshal(rules)
	os.WriteFile(testPath, data, 0644)

	mapfile := NewMapfile(testPath)
	mapfile.Load()

	groups := []string{"/group50"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapfile.MapUsername("user", groups, "/path")
	}
}

// BenchmarkUserExtraction benchmarks user info extraction
func BenchmarkUserExtraction(b *testing.B) {
	mapper := NewUserMapper("sub", "wlcg.groups", "")

	claims := map[string]interface{}{
		"sub": "testuser",
		"wlcg.groups": []interface{}{
			"group1", "group2", "group3",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapper.ExtractUserInfo(claims, "/path")
	}
}
