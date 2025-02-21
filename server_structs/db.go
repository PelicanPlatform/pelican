package server_structs

import "time"

type (
	ApiKeyCached struct {
		Token        string // "$ID.$SECRET_IN_HEX" string form
		Capabilities []string
		ExpiresAt    time.Time
	}

	ApiKey struct {
		ID          string `gorm:"primaryKey;column:id;type:text;not null;unique"`
		Name        string `gorm:"column:name;type:text"`
		HashedValue string `gorm:"column:hashed_value;type:text;not null"`
		Scopes      string `gorm:"column:scopes;type:text"`
		ExpiresAt   time.Time
		CreatedAt   time.Time
		CreatedBy   string `gorm:"column:created_by;type:text"`
	}
)
