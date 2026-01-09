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
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// MapfileRule represents a single rule in the mapfile for username mapping
type MapfileRule struct {
	Sub      *string `json:"sub"`
	Username *string `json:"username"`
	Path     *string `json:"path"`
	Group    *string `json:"group"`
	Result   string  `json:"result"`
	Ignore   *bool   `json:"ignore"`
	Comment  *string `json:"comment"`
}

// Mapfile represents the complete mapfile configuration
type Mapfile struct {
	Rules []MapfileRule `json:"-"`
	path  string
	mtime time.Time
	mu    sync.RWMutex
}

// NewMapfile creates a new mapfile loader
func NewMapfile(filePath string) *Mapfile {
	return &Mapfile{
		path: filePath,
	}
}

// Load reads and parses the mapfile from disk
func (m *Mapfile) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("failed to read mapfile: %w", err)
	}

	var rules []MapfileRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse mapfile JSON: %w", err)
	}

	// Get mtime for invalidation checks
	fileInfo, err := os.Stat(m.path)
	if err != nil {
		return fmt.Errorf("failed to stat mapfile: %w", err)
	}

	m.Rules = rules
	m.mtime = fileInfo.ModTime()
	return nil
}

// IsStale checks if the mapfile has been modified on disk
func (m *Mapfile) IsStale() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fileInfo, err := os.Stat(m.path)
	if err != nil {
		return true
	}

	return fileInfo.ModTime() != m.mtime
}

// ApplyRule applies a mapfile rule to determine the mapped username
// Returns the mapped username if the rule matches, empty string if no match
func (m *Mapfile) ApplyRule(rule MapfileRule, userClaim, groupClaims []string, requestPath string) string {
	// Ignore rules with Ignore flag set
	if rule.Ignore != nil && *rule.Ignore {
		return ""
	}

	// Check sub claim
	if rule.Sub != nil && len(userClaim) > 0 {
		if userClaim[0] != *rule.Sub {
			return ""
		}
	}

	// Check username claim
	if rule.Username != nil && len(userClaim) > 0 {
		if userClaim[0] != *rule.Username {
			return ""
		}
	}

	// Check path prefix
	if rule.Path != nil {
		rulePath := path.Clean(*rule.Path)
		normalizedReqPath := path.Clean(requestPath)
		// Ensure path ends with / for proper boundary checking
		if !strings.HasSuffix(rulePath, "/") {
			rulePath += "/"
		}
		if !strings.HasPrefix(normalizedReqPath, rulePath) && normalizedReqPath != strings.TrimSuffix(rulePath, "/") {
			return ""
		}
	}

	// Check group claim
	if rule.Group != nil {
		found := false
		for _, g := range groupClaims {
			if g == *rule.Group {
				found = true
				break
			}
		}
		if !found {
			return ""
		}
	}

	// All checks passed, return the result
	return rule.Result
}

// MapUsername applies mapfile rules to determine the mapped username
func (m *Mapfile) MapUsername(userClaim string, groupClaims []string, requestPath string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userClaimList := []string{}
	if userClaim != "" {
		userClaimList = []string{userClaim}
	}

	for _, rule := range m.Rules {
		if result := m.ApplyRule(rule, userClaimList, groupClaims, requestPath); result != "" {
			return result
		}
	}

	return ""
}

// UserInfo represents extracted user and group information from a token
type UserInfo struct {
	User        string
	Groups      []string
	MappedUser  string
	RequestPath string
}

// UserMapper handles username and group extraction from tokens with optional mapfile support
type UserMapper struct {
	usernameClaim string
	groupsClaim   string
	mapfile       *Mapfile
	mu            sync.RWMutex
}

// NewUserMapper creates a new user mapper
// usernameClaim: token claim to use for username (default: "sub")
// groupsClaim: token claim to use for groups (default: "wlcg.groups")
// mapfilePath: optional path to mapfile for username mapping
func NewUserMapper(usernameClaim, groupsClaim string, mapfilePath string) *UserMapper {
	um := &UserMapper{
		usernameClaim: usernameClaim,
		groupsClaim:   groupsClaim,
	}

	if mapfilePath != "" {
		um.mapfile = NewMapfile(mapfilePath)
		if err := um.mapfile.Load(); err != nil {
			log.Warnf("Failed to load mapfile: %v", err)
		}
	}

	return um
}

// RefreshMapfile reloads the mapfile if it has changed on disk
func (um *UserMapper) RefreshMapfile() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.mapfile == nil {
		return nil
	}

	if um.mapfile.IsStale() {
		return um.mapfile.Load()
	}

	return nil
}

// ExtractUserInfo extracts user and group information from token claims
func (um *UserMapper) ExtractUserInfo(tokenClaims map[string]interface{}, requestPath string) *UserInfo {
	um.mu.RLock()
	defer um.mu.RUnlock()

	ui := &UserInfo{
		User:        "nobody",
		Groups:      []string{},
		RequestPath: requestPath,
	}

	// Extract username from token using configured claim
	if username, ok := tokenClaims[um.usernameClaim].(string); ok {
		ui.User = username
	} else if sub, ok := tokenClaims["sub"].(string); ok {
		ui.User = sub
	}

	// Extract groups from token using configured claim
	if groups, ok := tokenClaims[um.groupsClaim]; ok {
		if groupList, ok := groups.([]interface{}); ok {
			for _, g := range groupList {
				if groupStr, ok := g.(string); ok {
					ui.Groups = append(ui.Groups, groupStr)
				}
			}
		}
	}

	// Apply mapfile mapping if available
	if um.mapfile != nil {
		if mapped := um.mapfile.MapUsername(ui.User, ui.Groups, requestPath); mapped != "" {
			ui.MappedUser = mapped
		}
	}

	return ui
}
