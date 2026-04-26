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

package database

// AUP-document storage. The active row in aup_documents is the
// authoritative copy of the policy users must accept. Source-of-truth
// resolution is in web_ui/aup.go:resolveAUP — this file is just the
// CRUD primitives.
//
// History matters: the table is append-only. An edit creates a new
// row and (in the same transaction) flips is_active off on the
// previous one, so users.aup_version always points at a row that
// actually existed when the user signed.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AUPDocument mirrors a row in the aup_documents table.
type AUPDocument struct {
	ID               string     `gorm:"primaryKey" json:"id"`
	Version          string     `gorm:"not null;unique" json:"version"`
	Content          string     `gorm:"not null" json:"content"`
	CreatedBy        string     `gorm:"not null;default:'unknown'" json:"createdBy"`
	AuthMethod       AuthMethod `gorm:"not null;default:''" json:"authMethod"`
	AuthMethodID     string     `gorm:"not null;default:''" json:"authMethodId,omitempty"`
	LastUpdatedLabel string     `gorm:"not null;default:''" json:"lastUpdated,omitempty"`
	IsActive         bool       `gorm:"not null;default:false" json:"isActive"`
	CreatedAt        time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

// HashAUPContent returns the canonical version string for a piece of
// AUP content. Same shape as the existing whoami / handleGetAUP
// version field (16 hex chars of SHA-256), so the IDs are
// interchangeable across the gate, the user record, and this table.
func HashAUPContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])[:16]
}

// GetActiveAUPDocument returns the active AUP row, if one exists.
// Returns gorm.ErrRecordNotFound when no operator-edited copy has
// ever been saved (the runtime then falls through to the configured
// file or the embedded default).
func GetActiveAUPDocument(db *gorm.DB) (*AUPDocument, error) {
	doc := &AUPDocument{}
	if err := db.Where("is_active = ?", true).First(doc).Error; err != nil {
		return nil, err
	}
	return doc, nil
}

// GetAUPDocumentByVersion looks up a specific historical version. Used
// by versioned AUP URLs (`GET /aup/:version`) and by audit tooling that
// needs the exact text a given user signed.
func GetAUPDocumentByVersion(db *gorm.DB, version string) (*AUPDocument, error) {
	doc := &AUPDocument{}
	if err := db.Where("version = ?", version).First(doc).Error; err != nil {
		return nil, err
	}
	return doc, nil
}

// ListAUPDocuments returns every persisted AUP version, newest first.
// Powers the admin "AUP history" view; the active version is whichever
// row has is_active = true.
func ListAUPDocuments(db *gorm.DB) ([]AUPDocument, error) {
	var docs []AUPDocument
	if err := db.Order("created_at DESC").Find(&docs).Error; err != nil {
		return nil, err
	}
	return docs, nil
}

// SaveActiveAUPDocument persists a new AUP version and atomically
// flips it to active, deactivating whichever row was active before.
//
// Behavior:
//   - The version hash is computed from the supplied content; callers
//     do not pass it.
//   - If the same content (same hash) is already in the table, the
//     existing row is reused — content stays unchanged but
//     is_active flips to that row, and its CreatedBy / lastUpdatedLabel
//     audit fields are refreshed to the new edit.
//   - The single-row "active" invariant is enforced by an UPDATE
//     inside the transaction, not by any caller-provided ordering.
//   - lastUpdatedLabel is the human-readable date string the operator
//     wants in the AUP footer ("This text was last updated on …").
//     Empty is fine; the UI falls back to the row's CreatedAt.
//
// Returns the row that ended up active (whether new or reused).
func SaveActiveAUPDocument(db *gorm.DB, content, lastUpdatedLabel string, creator Creator) (*AUPDocument, error) {
	if strings.TrimSpace(content) == "" {
		return nil, errors.New("AUP content must not be empty")
	}
	version := HashAUPContent(content)
	now := time.Now()

	var result AUPDocument
	err := db.Transaction(func(tx *gorm.DB) error {
		// Step 1 — deactivate whichever row is currently active. This
		// must happen first so the partial unique index on (is_active)
		// stays satisfied when we flip the new row to active below.
		if err := tx.Model(&AUPDocument{}).
			Where("is_active = ?", true).
			Update("is_active", false).Error; err != nil {
			return err
		}

		// Step 2 — find an existing row with the same content (same
		// hash) and reuse it; otherwise create a fresh row.
		existing := &AUPDocument{}
		err := tx.Where("version = ?", version).First(existing).Error
		if err == nil {
			updates := map[string]interface{}{
				"is_active":          true,
				"created_by":         creatorOrUnknown(creator.UserID),
				"auth_method":        creator.AuthMethod,
				"auth_method_id":     creator.AuthMethodID,
				"last_updated_label": lastUpdatedLabel,
				"created_at":         now,
			}
			if err := tx.Model(existing).Updates(updates).Error; err != nil {
				return err
			}
			result = *existing
			result.IsActive = true
			result.CreatedBy = creatorOrUnknown(creator.UserID)
			result.AuthMethod = creator.AuthMethod
			result.AuthMethodID = creator.AuthMethodID
			result.LastUpdatedLabel = lastUpdatedLabel
			result.CreatedAt = now
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		slug, slugErr := generateSlug()
		if slugErr != nil {
			return slugErr
		}
		fresh := AUPDocument{
			ID:               slug,
			Version:          version,
			Content:          content,
			CreatedBy:        creatorOrUnknown(creator.UserID),
			AuthMethod:       creator.AuthMethod,
			AuthMethodID:     creator.AuthMethodID,
			LastUpdatedLabel: lastUpdatedLabel,
			IsActive:         true,
			CreatedAt:        now,
		}
		if err := tx.Create(&fresh).Error; err != nil {
			return err
		}
		result = fresh
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
