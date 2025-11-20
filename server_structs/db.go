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
	ServerLocalMetadata struct {
		ID        string         `gorm:"primaryKey;column:id;type:TEXT"`
		Name      string         `gorm:"column:name;type:TEXT;not null"`
		IsOrigin  bool           `gorm:"column:is_origin;type:BOOLEAN;not null;default:false"`
		IsCache   bool           `gorm:"column:is_cache;type:BOOLEAN;not null;default:false"`
		CreatedAt time.Time      `gorm:"column:created_at;autoCreateTime"`
		UpdatedAt time.Time      `gorm:"column:updated_at;autoUpdateTime"`
		DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index"`
	}
)
