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

package server_structs

import (
	"crypto/rand"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type RegistrationStatus string

// The AdminMetadata is used in [Namespace] as a marshaled JSON string
// to be stored in registry DB.
//
// The UserID and SecurityContactUserID are meant to correspond to the "sub" claim of the user token that
// the OAuth client issues if the user is logged in using OAuth, or it should be
// "admin" from local password-based authentication.
//
// To prevent users from writing to certain fields (readonly), you may use "post" tag
// with value "exclude". This will exclude the field from user's create/update requests
// and the field will also be excluded from field discovery endpoint (OPTION method).
//
// We use validator package to validate struct fields from user requests. If a field is
// required, add `validate:"required"` to that field. This tag will also be used by fields discovery
// endpoint to tell the UI if a field is required. For other validator tags,
// visit: https://pkg.go.dev/github.com/go-playground/validator/v10
type AdminMetadata struct {
	UserID                string             `json:"user_id" post:"exclude"` // "sub" claim of user JWT who requested registration
	Description           string             `json:"description"`
	SiteName              string             `json:"site_name"`
	Institution           string             `json:"institution" validate:"required"`                                                                                // the unique identifier of the institution
	SecurityContactUserID string             `json:"security_contact_user_id" description:"User Identifier of the user responsible for the security of the service"` // "sub" claim of user who is responsible for taking security concern
	Status                RegistrationStatus `json:"status" post:"exclude"`
	ApproverID            string             `json:"approver_id" post:"exclude"` // "sub" claim of user JWT who approved registration
	ApprovedAt            time.Time          `json:"approved_at" post:"exclude"`
	CreatedAt             time.Time          `json:"created_at" post:"exclude"`
	UpdatedAt             time.Time          `json:"updated_at" post:"exclude"`
}

type Namespace struct {
	ID            int                    `json:"id" post:"exclude" gorm:"primaryKey"`
	Prefix        string                 `json:"prefix" validate:"required"`
	Pubkey        string                 `json:"pubkey" validate:"required" description:"Pubkey is your Pelican server public key in JWKS form"`
	Identity      string                 `json:"identity" post:"exclude"`
	AdminMetadata AdminMetadata          `json:"admin_metadata" gorm:"serializer:json"`
	CustomFields  map[string]interface{} `json:"custom_fields" gorm:"serializer:json"`
}

type (
	CheckNamespaceExistsReq struct {
		Prefix string `json:"prefix"`
		PubKey string `json:"pubkey"`
	}

	CheckNamespaceExistsRes struct {
		PrefixExists bool   `json:"prefix_exists"`
		KeyMatch     bool   `json:"key_match"`
		Message      string `json:"message"`
		Error        string `json:"error"`
	}

	CheckNamespaceStatusReq struct {
		Prefix string `json:"prefix"`
	}

	CheckNamespaceStatusRes struct {
		Approved bool `json:"approved"`
	}

	CheckNamespaceCompleteReq struct {
		Prefixes []string `json:"prefixes"`
	}

	NamespaceCompletenessResult struct {
		EditUrl   string `json:"edit_url"`
		Completed bool   `json:"complete"`
		Msg       string `json:"msg"`
	}

	CheckNamespaceCompleteRes struct {
		Results map[string]NamespaceCompletenessResult `json:"results"`
	}
)

const (
	RegPending  RegistrationStatus = "Pending"
	RegApproved RegistrationStatus = "Approved"
	RegDenied   RegistrationStatus = "Denied"
	RegUnknown  RegistrationStatus = "Unknown"
)

func (rs RegistrationStatus) String() string {
	return string(rs)
}

func (rs RegistrationStatus) LowerString() string {
	return strings.ToLower(string(rs))
}

func (a AdminMetadata) Equal(b AdminMetadata) bool {
	return a.UserID == b.UserID &&
		a.Description == b.Description &&
		a.SiteName == b.SiteName &&
		a.Institution == b.Institution &&
		a.SecurityContactUserID == b.SecurityContactUserID &&
		a.Status == b.Status &&
		a.ApproverID == b.ApproverID &&
		a.ApprovedAt.Equal(b.ApprovedAt) &&
		a.CreatedAt.Equal(b.CreatedAt) &&
		a.UpdatedAt.Equal(b.UpdatedAt)
}

func (Namespace) TableName() string {
	return "namespace"
}

func IsValidRegStatus(s string) bool {
	return s == "Pending" || s == "Approved" || s == "Denied" || s == "Unknown"
}

// Server represents a Pelican server (origin or cache) in the registry
type Server struct {
	ID        string    `json:"id" gorm:"primaryKey" validate:"len=7,regexp=^[a-z0-9]{7}$" description:"Auto-generated 7-character random string composed of a-z and 0-9"`
	Name      string    `json:"name" gorm:"uniqueIndex" validate:"required"`
	IsOrigin  bool      `json:"is_origin" gorm:"default:false"`
	IsCache   bool      `json:"is_cache" gorm:"default:false"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `json:"updated_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`
}

// Service maps a server to its namespace representation
type Service struct {
	ID          int       `json:"id" post:"exclude" gorm:"primaryKey"`
	ServerID    string    `json:"server_id" validate:"required" gorm:"index"`
	NamespaceID int       `json:"namespace_id" validate:"required" gorm:"index"`
	CreatedAt   time.Time `json:"created_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time `json:"updated_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`

	// Foreign key relationships
	Server    Server    `json:"server" gorm:"foreignKey:ServerID;references:ID;constraint:OnDelete:CASCADE"`
	Namespace Namespace `json:"namespace" gorm:"foreignKey:NamespaceID;references:ID;constraint:OnDelete:CASCADE"`
}

// Endpoint represents a network address for a server
type Endpoint struct {
	ID        int       `json:"id" post:"exclude" gorm:"primaryKey"`
	ServerID  string    `json:"server_id" validate:"required" gorm:"index"`
	Endpoint  string    `json:"endpoint" validate:"required"`
	CreatedAt time.Time `json:"created_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `json:"updated_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`

	// Foreign key relationship
	Server Server `json:"server" gorm:"foreignKey:ServerID;references:ID;constraint:OnDelete:CASCADE"`
}

// Contact represents contact information for a server
type Contact struct {
	ID          int       `json:"id" post:"exclude" gorm:"primaryKey"`
	ServerID    string    `json:"server_id" validate:"required" gorm:"index"`
	FullName    string    `json:"full_name" validate:"required"`
	ContactInfo string    `json:"contact_info" validate:"required" description:"Email, phone, or other contact information"`
	CreatedAt   time.Time `json:"created_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time `json:"updated_at" post:"exclude" gorm:"default:CURRENT_TIMESTAMP"`

	// Foreign key relationship
	Server Server `json:"server" gorm:"foreignKey:ServerID;references:ID;constraint:OnDelete:CASCADE"`
}

// Define the table name for each struct for GORM
func (Server) TableName() string {
	return "servers"
}

func (Service) TableName() string {
	return "services"
}

func (Endpoint) TableName() string {
	return "endpoints"
}

func (Contact) TableName() string {
	return "contacts"
}

// ServerNamespace combines Server and Namespace structs with flattened fields
type ServerNamespace struct {
	// Server fields
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsOrigin  bool      `json:"is_origin"`
	IsCache   bool      `json:"is_cache"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Namespace fields (ID renamed to NsID to avoid conflict)
	NsID          int                    `json:"ns_id"`
	Prefix        string                 `json:"prefix"`
	Pubkey        string                 `json:"pubkey"`
	Identity      string                 `json:"identity"`
	AdminMetadata AdminMetadata          `json:"admin_metadata"`
	CustomFields  map[string]interface{} `json:"custom_fields"`
}

// BeforeCreate GORM hook to auto-generate Server ID
func (s *Server) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		id, err := generateUniqueServerID(tx)
		if err != nil {
			return err
		}
		s.ID = id
	}
	return nil
}

// Ensure the Server ID is unique in the database
func generateUniqueServerID(tx *gorm.DB) (string, error) {
	const maxRetries = 10

	for attempt := 0; attempt < maxRetries; attempt++ {
		id, err := generateServerID()
		if err != nil {
			return "", err
		}

		// Check if ID already exists
		var count int64
		err = tx.Model(&Server{}).Where("id = ?", id).Count(&count).Error
		if err != nil {
			return "", err
		}

		// If ID doesn't exist, we found a unique one
		if count == 0 {
			return id, nil
		}

		// ID exists, try again (collision detected)
	}

	return "", errors.Errorf("failed to generate unique server ID after %d attempts", maxRetries)
}

// Create a 7-character random string using a-z and 0-9
func generateServerID() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 7)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}
