package server_structs

import (
	"time"

	"gorm.io/gorm"
)

type (
	ApiKeyCached struct {
		Token        string // "$ID.$SECRET_IN_HEX" string form
		Capabilities []string
		ExpiresAt    time.Time
	}

	ApiKey struct {
		ID          string    `gorm:"primaryKey;column:id;type:text;not null;unique" json:"id"`
		Name        string    `gorm:"column:name;type:text" json:"name"`
		HashedValue string    `gorm:"column:hashed_value;type:text;not null" json:"-"`
		Scopes      string    `gorm:"column:scopes;type:text" json:"scopes"`
		ExpiresAt   time.Time `json:"expiration"`
		CreatedAt   time.Time `json:"createdAt"`
		CreatedBy   string    `gorm:"column:created_by;type:text" json:"createdBy"`
	}

	ApiKeyResponse struct {
		ID          string    `gorm:"primaryKey;column:id;type:text;not null;unique" json:"id"`
		Name        string    `gorm:"column:name;type:text" json:"name"`
		HashedValue string    `gorm:"column:hashed_value;type:text;not null" json:"-"`
		Scopes      []string  `gorm:"column:scopes;type:text" json:"scopes"`
		ExpiresAt   time.Time `json:"expiration"`
		CreatedAt   time.Time `json:"createdAt"`
		CreatedBy   string    `gorm:"column:created_by;type:text" json:"createdBy"`
	}

	// ServerLocalMetadata is the local record of Origin/Cache server's metadata it fetched from the Registry,
	// Maps to the `service_names` table in the database.
	ServerLocalMetadata struct {
		ID        string         `gorm:"primaryKey;column:id;type:TEXT" json:"id"`
		Name      string         `gorm:"column:name;type:TEXT;not null" json:"name"`
		Type      string         `gorm:"column:type;type:TEXT;not null" json:"type"` // "origin" or "cache"
		CreatedAt time.Time      `gorm:"column:created_at;autoCreateTime" json:"createdAt"`
		UpdatedAt time.Time      `gorm:"column:updated_at;autoUpdateTime" json:"updatedAt"`
		DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
	}
)

// TableName overrides the default table name to use the existing `service_names` table
func (ServerLocalMetadata) TableName() string {
	return "service_names"
}
