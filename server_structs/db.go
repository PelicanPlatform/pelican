package server_structs

import "time"

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
)
