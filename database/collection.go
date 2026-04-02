package database

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	ErrForbidden = errors.New("forbidden")
	// ErrReservedGroupPrefix indicates a requested group name collides with the
	// reserved prefix used for automatically managed personal groups.
	ErrReservedGroupPrefix = errors.New("reserved group name prefix 'user-'")
)

type Visibility string

const (
	VisibilityPrivate Visibility = "private"
	VisibilityPublic  Visibility = "public"
)

type AclRole string

const (
	AclRoleRead  AclRole = "read"
	AclRoleWrite AclRole = "write"
	AclRoleOwner AclRole = "owner"
)

var (
	ScopeToRole map[token_scopes.TokenScope][]AclRole = map[token_scopes.TokenScope][]AclRole{
		token_scopes.Collection_Read:   {AclRoleRead, AclRoleWrite, AclRoleOwner},
		token_scopes.Collection_Modify: {AclRoleWrite, AclRoleOwner},
		token_scopes.Collection_Delete: {AclRoleOwner},
	}
)

type Collection struct {
	ID          string               `gorm:"primaryKey" json:"id"`
	Name        string               `gorm:"not null;uniqueIndex:idx_owner_name" json:"name"`
	Description string               `json:"description"`
	Owner       string               `gorm:"not null;uniqueIndex:idx_owner_name" json:"owner"`
	Namespace   string               `gorm:"not null" json:"namespace"`
	Visibility  Visibility           `gorm:"not null;default:private" json:"visibility"`
	CreatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	Members     []CollectionMember   `gorm:"foreignKey:CollectionID" json:"members"`
	ACLs        []CollectionACL      `gorm:"foreignKey:CollectionID" json:"acls"`
	Metadata    []CollectionMetadata `gorm:"foreignKey:CollectionID" json:"metadata"`
}

type CollectionMember struct {
	CollectionID string    `gorm:"primaryKey" json:"collectionId"`
	ObjectURL    string    `gorm:"primaryKey" json:"objectUrl"` // full pelican:// URL
	AddedBy      string    `gorm:"not null" json:"createdBy"`
	AddedAt      time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

type CollectionACL struct {
	CollectionID string     `gorm:"primaryKey" json:"collectionId"`
	GroupID      string     `gorm:"primaryKey" json:"groupId"`
	Role         AclRole    `gorm:"primaryKey;not null" json:"role"`
	GrantedBy    string     `gorm:"not null" json:"createdBy"`
	GrantedAt    time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt"`
}

type CollectionMetadata struct {
	CollectionID string `gorm:"primaryKey" json:"collectionId"`
	Key          string `gorm:"primaryKey;not null" json:"key"`
	Value        string `gorm:"not null" json:"value"`
}

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
)

type User struct {
	ID          string     `gorm:"primaryKey" json:"id"`
	Username    string     `gorm:"not null;uniqueIndex:idx_user_issuer" json:"username"`
	Sub         string     `gorm:"not null;uniqueIndex:idx_user_sub_issuer" json:"sub"`
	Issuer      string     `gorm:"not null;uniqueIndex:idx_user_issuer;uniqueIndex:idx_user_sub_issuer" json:"issuer"`
	Status      UserStatus `gorm:"not null;default:active" json:"status"`
	LastLoginAt *time.Time `json:"lastLoginAt"`
	DisplayName string     `gorm:"not null;default:''" json:"displayName"`
	AUPVersion  string     `gorm:"not null;default:''" json:"aupVersion"`
	AUPAgreedAt *time.Time `json:"aupAgreedAt"`
	CreatedAt   time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

type AdminType string

const (
	AdminTypeUser  AdminType = "user"
	AdminTypeGroup AdminType = "group"
)

type Group struct {
	ID          string        `gorm:"primaryKey" json:"id"`
	Name        string        `gorm:"not null;unique" json:"name"`
	Description string        `json:"description"`
	CreatedBy   string        `gorm:"not null" json:"createdBy"`
	OwnerID     string        `gorm:"not null;default:''" json:"ownerId"`
	AdminID     string        `gorm:"not null;default:''" json:"adminId"`
	AdminType   AdminType     `gorm:"not null;default:''" json:"adminType"`
	CreatedAt   time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	Members     []GroupMember `gorm:"foreignKey:GroupID" json:"members"`
}

type GroupMember struct {
	GroupID string    `gorm:"primaryKey" json:"groupId"`
	UserID  string    `gorm:"primaryKey" json:"userId"`
	User    User      `gorm:"foreignKey:UserID" json:"user"`
	AddedBy string    `gorm:"not null" json:"createdBy"`
	AddedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

type GroupInviteLink struct {
	ID          string     `gorm:"primaryKey" json:"id"`
	GroupID     string     `gorm:"not null;default:''" json:"groupId"`
	HashedToken string     `gorm:"column:invite_token;not null;unique" json:"-"`
	CreatedBy   string     `gorm:"not null" json:"createdBy"`
	CreatedAt   time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	ExpiresAt   time.Time  `gorm:"not null" json:"expiresAt"`
	IsSingleUse bool       `gorm:"not null;default:false" json:"isSingleUse"`
	RedeemedBy  string     `gorm:"not null;default:''" json:"redeemedBy"`
	RedeemedAt  *time.Time `json:"redeemedAt"`
	Revoked     bool       `gorm:"not null;default:false" json:"revoked"`
}

type UserIdentity struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	UserID    string    `gorm:"not null" json:"userId"`
	Sub       string    `gorm:"not null;uniqueIndex:idx_identity_sub_issuer" json:"sub"`
	Issuer    string    `gorm:"not null;uniqueIndex:idx_identity_sub_issuer" json:"issuer"`
	CreatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

func generateSlug() (string, error) {
	slug := make([]byte, 16)
	_, err := rand.Read(slug)
	if err != nil {
		return "", err
	}
	slugStr := hex.EncodeToString(slug)
	slugStr = slugStr[:8]
	return slugStr, nil
}

func CreateCollection(db *gorm.DB, name, description, owner, namespace string, visibility Visibility) (*Collection, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:          slug,
		Name:        name,
		Description: description,
		Owner:       owner,
		Namespace:   namespace,
		Visibility:  visibility,
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(collection); result.Error != nil {
			return result.Error
		}

		// Also create the owner ACL for the owner's primary group
		ownerGroup := "user-" + owner
		ownerAcl := &CollectionACL{
			CollectionID: collection.ID,
			GroupID:      ownerGroup,
			Role:         AclRoleOwner,
			GrantedBy:    owner,
		}
		if result := tx.Create(ownerAcl); result.Error != nil {
			return result.Error
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return collection, nil
}

func CreateCollectionWithMetadata(db *gorm.DB, name, description, owner, namespace string, visibility Visibility, metadata map[string]string) (*Collection, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:          slug,
		Name:        name,
		Description: description,
		Owner:       owner,
		Namespace:   namespace,
		Visibility:  visibility,
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(collection); result.Error != nil {
			return result.Error
		}

		if len(metadata) > 0 {
			metadataEntries := make([]CollectionMetadata, 0, len(metadata))
			for k, v := range metadata {
				metadataEntries = append(metadataEntries, CollectionMetadata{
					CollectionID: collection.ID,
					Key:          k,
					Value:        v,
				})
			}
			if result := tx.Create(&metadataEntries); result.Error != nil {
				return result.Error
			}
		}

		// Also create the owner ACL for the owner's primary group
		ownerGroup := "user-" + owner
		ownerAcl := &CollectionACL{
			CollectionID: collection.ID,
			GroupID:      ownerGroup,
			Role:         AclRoleOwner,
			GrantedBy:    owner,
		}
		if result := tx.Create(ownerAcl); result.Error != nil {
			return result.Error
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return collection, nil
}

func ListCollections(db *gorm.DB, user string, groups []string) ([]Collection, error) {
	collections := []Collection{}
	// Every user is part of their own user group, ensure this is in the slice
	userGroup := "user-" + user
	if !slices.Contains(groups, userGroup) {
		groups = append(groups, userGroup)
	}
	// First, get all public collections.
	if result := db.Where("visibility = ?", VisibilityPublic).Find(&collections); result.Error != nil {
		return nil, result.Error
	}
	// Then, get all collections for which the user has a read ACL.
	var aclCollections []Collection
	if result := db.
		Joins("JOIN collection_acls ON collections.id = collection_acls.collection_id").
		Where("collection_acls.group_id IN ? AND collection_acls.role IN ?", groups, ScopeToRole[token_scopes.Collection_Read]).
		Find(&aclCollections); result.Error != nil {
		return nil, result.Error
	}
	// Merge the two lists, avoiding duplicates.
	for _, aclCol := range aclCollections {
		found := false
		for _, pubCol := range collections {
			if aclCol.ID == pubCol.ID {
				found = true
				break
			}
		}
		if !found {
			collections = append(collections, aclCol)
		}
	}
	return collections, nil
}

func GetCollection(db *gorm.DB, id string, user string, groups []string) (*Collection, error) {
	collection := &Collection{}
	if result := db.Preload("Members").Preload("ACLs").Preload("Metadata").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	if collection.Visibility == VisibilityPublic {
		return collection, nil
	}

	err := validateACL(collection, user, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	return collection, nil
}

func GetCollectionMembers(db *gorm.DB, id, user string, groups []string, since *time.Time, limit int) ([]CollectionMember, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	err := validateACL(collection, user, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	members := []CollectionMember{}
	query := db.Where("collection_id = ?", id)
	if since != nil {
		query = query.Where("added_at > ?", *since)
	}
	if limit > 0 {
		query = query.Limit(limit)
	}

	if result := query.Find(&members); result.Error != nil {
		return nil, result.Error
	}
	return members, nil
}

func GetCollectionMetadata(db *gorm.DB, id, user string, groups []string) ([]CollectionMetadata, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	err := validateACL(collection, user, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	metadata := []CollectionMetadata{}
	if result := db.Where("collection_id = ?", id).Find(&metadata); result.Error != nil {
		return nil, result.Error
	}
	return metadata, nil
}

func GetCollectionAcls(db *gorm.DB, id, user string, groups []string) ([]CollectionACL, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	// The spec says that owners and writers should be able to see the ACLs.
	// We can reuse the Collection_Modify scope for this.
	err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
	if err != nil {
		return nil, err
	}

	return collection.ACLs, nil
}

func GrantCollectionAcl(db *gorm.DB, id, user string, groups []string, groupId string, role AclRole, expiresAt *time.Time, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	// Resolve the provided group identifier (which may be the internal slug returned
	// by the create-group endpoint) to the human-readable group *name*.  The group
	// *name* is what’s shipped in the `wlcg.groups` claim of the JWT and therefore
	// what we should persist in the ACL for later comparisons during authorization.
	var grp Group
	if err := db.First(&grp, "id = ?", groupId).Error; err == nil {
		// We found the group by its slug; switch to using the group name.
		groupId = grp.Name
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		// It's possible the caller already provided the group *name*; try to look
		// it up by name to verify it exists (and to ensure a consistent casing).
		if err2 := db.First(&grp, "name = ?", groupId).Error; err2 == nil {
			groupId = grp.Name // Adopt the canonical name from the DB.
		} // else: leave groupId unchanged – we’ll trust the caller.
	} else {
		// Unexpected database error.
		return err
	}

	return db.Transaction(func(tx *gorm.DB) error {
		acl := CollectionACL{
			CollectionID: id,
			GroupID:      groupId,
			Role:         role,
			GrantedBy:    user,
			ExpiresAt:    expiresAt,
		}
		// Use OnConflict to either create or update the ACL
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "collection_id"}, {Name: "group_id"}, {Name: "role"}},
			DoUpdates: clause.AssignmentColumns([]string{"granted_by", "expires_at"}),
		}).Create(&acl).Error
	})
}

func RevokeCollectionAcl(db *gorm.DB, id, user string, groups []string, groupId string, role AclRole, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("collection_id = ? AND group_id = ? AND role = ?", id, groupId, role).Delete(&CollectionACL{}); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func UpsertCollectionMetadata(db *gorm.DB, id, user string, groups []string, key, value string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		metadata := CollectionMetadata{
			CollectionID: id,
			Key:          key,
			Value:        value,
		}
		// Use OnConflict to either create or update the metadata
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "collection_id"}, {Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value"}),
		}).Create(&metadata).Error
	})
}

func DeleteCollectionMetadata(db *gorm.DB, id, user string, groups []string, key string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("collection_id = ? AND key = ?", id, key).Delete(&CollectionMetadata{}); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func UpdateCollection(db *gorm.DB, id, user string, groups []string, name, description *string, visibility *Visibility, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	updates := make(map[string]interface{})
	if name != nil {
		updates["name"] = *name
	}
	if description != nil {
		updates["description"] = *description
	}
	if visibility != nil {
		updates["visibility"] = *visibility
	}

	if len(updates) == 0 {
		return nil
	}

	return db.Model(&Collection{}).Where("id = ?", id).Updates(updates).Error
}

func AddCollectionMembers(db *gorm.DB, id string, members []string, addedBy string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, addedBy, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	// Enforce that each member belongs to the collection's namespace
	namespace := collection.Namespace
	for _, memberUrl := range members {
		purl, err := pelican_url.Parse(memberUrl, []pelican_url.ParseOption{}, []pelican_url.DiscoveryOption{})
		if err != nil {
			return fmt.Errorf("failed to parse member URL '%s': %w", memberUrl, err)
		}
		path := purl.Path
		if !strings.HasPrefix(path, namespace) {
			return fmt.Errorf("object URL '%s' does not belong to collection namespace '%s'", memberUrl, namespace)
		}
		// If the namespace prefix matches but is followed by additional characters that don't begin with '/', reject as well (e.g., '/test10')
		if len(path) > len(namespace) && path[len(namespace)] != '/' {
			return fmt.Errorf("object URL '%s' does not belong to collection namespace '%s'", memberUrl, namespace)
		}
	}

	records := make([]CollectionMember, 0, len(members))
	for _, member := range members {
		records = append(records, CollectionMember{
			CollectionID: id,
			ObjectURL:    member,
			AddedBy:      addedBy,
		})
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(&records); result.Error != nil {
			return result.Error
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func RemoveCollectionMembers(db *gorm.DB, id string, members []string, user string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("collection_id = ? AND object_url IN ?", id, members).Delete(&CollectionMember{}); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func DeleteCollection(db *gorm.DB, id string, owner string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, owner, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// delete all references to the collection
		if result := tx.Where("collection_id = ?", id).Delete(&CollectionMember{}); result.Error != nil {
			return result.Error
		}
		if result := tx.Where("collection_id = ?", id).Delete(&CollectionACL{}); result.Error != nil {
			return result.Error
		}
		if result := tx.Where("collection_id = ?", id).Delete(&CollectionMetadata{}); result.Error != nil {
			return result.Error
		}
		if result := tx.Delete(collection); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func validateACL(collection *Collection, user string, groups []string, scope token_scopes.TokenScope) error {
	roles, ok := ScopeToRole[scope]
	if !ok {
		return fmt.Errorf("invalid scope: %s", scope.String())
	}

	// Every user is part of their own user group, ensure this is in the slice
	userGroup := "user-" + user
	if !slices.Contains(groups, userGroup) {
		groups = append(groups, userGroup)
	}

	// for each acl, check if a user's group is the group in the ACL and has the required role
	for _, acl := range collection.ACLs {
		for _, group := range groups {
			if acl.GroupID == group && slices.Contains(roles, acl.Role) {
				if acl.ExpiresAt != nil && acl.ExpiresAt.Before(time.Now()) {
					return ErrForbidden
				}
				return nil
			}
		}
	}

	return ErrForbidden
}

func GetUserByUsername(db *gorm.DB, username string) (*User, error) {
	user := &User{}
	if err := db.Where("username = ?", username).First(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func GetOrCreateUser(db *gorm.DB, username string, sub string, issuer string) (*User, error) {
	user := &User{}
	err := db.Where("sub = ? AND issuer = ?", sub, issuer).First(user).Error
	if err == nil {
		// User found, return existing user
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// User not found, create one
	return CreateUser(db, username, sub, issuer)
}

func GetUserByID(db *gorm.DB, id string) (*User, error) {
	user := &User{}
	if err := db.First(user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func CreateUser(db *gorm.DB, username string, sub string, issuer string) (*User, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}
	newUser := &User{
		ID:       slug,
		Username: username,
		Sub:      sub,
		Issuer:   issuer,
	}
	if err := db.Create(newUser).Error; err != nil {
		// Check if the error is a unique constraint violation
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, errors.New("user shares either username or (sub and iss) with another")
		}
		return nil, err
	}
	return newUser, nil
}

func UpdateUser(db *gorm.DB, id string, username, sub, issuer *string) error {
	updates := make(map[string]interface{})
	if username != nil {
		updates["username"] = *username
	}
	if sub != nil {
		updates["sub"] = *sub
	}
	if issuer != nil {
		updates["issuer"] = *issuer
	}

	if len(updates) == 0 {
		return nil
	}

	if err := db.Model(&User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	return nil
}

func CreateGroup(db *gorm.DB, name, description, createdByUserID string, groups []string) (*Group, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	// Disallow creating groups that start with the reserved personal-group prefix.
	if strings.HasPrefix(name, "user-") {
		return nil, ErrReservedGroupPrefix
	}

	group := &Group{
		ID:          slug,
		Name:        name,
		Description: description,
		CreatedBy:   createdByUserID,
		OwnerID:     createdByUserID,
	}

	if result := db.Create(group); result.Error != nil {
		return nil, result.Error
	}

	return group, nil
}

func GetGroupWithMembers(db *gorm.DB, groupId string) (*Group, error) {
	group := &Group{}
	if err := db.Preload("Members.User").First(group, "id = ?", groupId).Error; err != nil {
		return nil, err
	}
	return group, nil
}

func ListGroups(db *gorm.DB) ([]Group, error) {
	groups := []Group{}
	if err := db.Preload("Members.User").Find(&groups).Error; err != nil {
		return nil, err
	}
	return groups, nil
}

// isGroupOwnerOrAdmin checks whether the given userID is the group's owner,
// admin (when admin_type is 'user'), or a member of the admin group (when
// admin_type is 'group'). System admins bypass this check.
func isGroupOwnerOrAdmin(db *gorm.DB, group *Group, userID string, isSystemAdmin bool) bool {
	if isSystemAdmin {
		return true
	}
	// Owner can always manage
	if group.OwnerID == userID {
		return true
	}
	// Fallback to legacy CreatedBy for groups that predate the owner_id column
	if group.OwnerID == "" && group.CreatedBy == userID {
		return true
	}
	// Check admin
	if group.AdminID != "" {
		if group.AdminType == AdminTypeUser && group.AdminID == userID {
			return true
		}
		if group.AdminType == AdminTypeGroup {
			// Check if the user is a member of the admin group
			var count int64
			db.Model(&GroupMember{}).Where("group_id = ? AND user_id = ?", group.AdminID, userID).Count(&count)
			if count > 0 {
				return true
			}
		}
	}
	return false
}

// isGroupOwnerOnly checks whether the given userID is the group's owner.
// Only owners can change the owner or admin settings.
func isGroupOwnerOnly(group *Group, userID string, isSystemAdmin bool) bool {
	if isSystemAdmin {
		return true
	}
	if group.OwnerID == userID {
		return true
	}
	// Fallback to legacy CreatedBy for groups that predate the owner_id column
	if group.OwnerID == "" && group.CreatedBy == userID {
		return true
	}
	return false
}

func UpdateGroup(db *gorm.DB, id string, name, description *string, requestorUserID string, isAdmin bool) error {
	updates := make(map[string]interface{})
	if name != nil {
		if strings.HasPrefix(*name, "user-") {
			return ErrReservedGroupPrefix
		}
		updates["name"] = *name
	}
	if description != nil {
		updates["description"] = *description
	}

	if len(updates) == 0 {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// Verify group exists and check authorization inside the transaction
		var group Group
		if err := tx.First(&group, "id = ?", id).Error; err != nil {
			return err
		}

		if !isGroupOwnerOrAdmin(tx, &group, requestorUserID, isAdmin) {
			return ErrForbidden
		}

		return tx.Model(&Group{}).Where("id = ?", id).Updates(updates).Error
	})
}

// UpdateGroupOwnership updates the owner and/or admin settings of a group.
// Only the group owner (or system admin) may change these settings.
func UpdateGroupOwnership(db *gorm.DB, id string, ownerID, adminID *string, adminType *AdminType, requestorUserID string, isSystemAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var group Group
		if err := tx.First(&group, "id = ?", id).Error; err != nil {
			return err
		}

		if !isGroupOwnerOnly(&group, requestorUserID, isSystemAdmin) {
			return ErrForbidden
		}

		updates := make(map[string]interface{})
		if ownerID != nil {
			// Verify the new owner exists
			var user User
			if err := tx.First(&user, "id = ?", *ownerID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return errors.New("new owner user does not exist")
				}
				return err
			}
			updates["owner_id"] = *ownerID
		}
		if adminID != nil {
			updates["admin_id"] = *adminID
		}
		if adminType != nil {
			updates["admin_type"] = *adminType
		}

		if len(updates) == 0 {
			return nil
		}

		return tx.Model(&Group{}).Where("id = ?", id).Updates(updates).Error
	})
}

func AddGroupMember(db *gorm.DB, groupId, userId, addedByUserId string, isAdmin bool) error {
	var group Group
	if err := db.First(&group, "id = ?", groupId).Error; err != nil {
		return err
	}

	if !isGroupOwnerOrAdmin(db, &group, addedByUserId, isAdmin) {
		return ErrForbidden
	}

	// Verify the user exists
	var user User
	if err := db.First(&user, "id = ?", userId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user does not exist")
		}
		return err
	}

	groupMember := &GroupMember{
		GroupID: groupId,
		UserID:  userId,
		AddedBy: addedByUserId,
	}
	if result := db.Create(groupMember); result.Error != nil {
		// Check if the error is a unique constraint violation
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return errors.New("user is already a member of the group")
		}
		return result.Error
	}
	return nil
}

func RemoveGroupMember(db *gorm.DB, groupId, userId, removedByUserId string, isAdmin bool) error {
	var group Group
	if err := db.First(&group, "id = ?", groupId).Error; err != nil {
		return err
	}

	// Allow removal if user is owner, admin, or system admin
	if !isGroupOwnerOrAdmin(db, &group, removedByUserId, isAdmin) {
		return ErrForbidden
	}

	if result := db.Where("group_id = ? AND user_id = ?", groupId, userId).Delete(&GroupMember{}); result.Error != nil {
		return result.Error
	}
	return nil
}

func GetMemberGroups(db *gorm.DB, userId string) ([]Group, error) {
	groups := []Group{}

	result := db.Model(&Group{}).
		Joins("JOIN group_members ON groups.id = group_members.group_id").
		Where("group_members.user_id = ?", userId).
		Select("groups.id, groups.name").
		Find(&groups)
	if result.Error != nil {
		return nil, result.Error
	}
	return groups, nil
}

func ListUsers(db *gorm.DB) ([]User, error) {
	users := []User{}
	if err := db.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func GetAllCollections(db *gorm.DB) ([]Collection, error) {
	var collections []Collection
	if result := db.Find(&collections); result.Error != nil {
		return nil, result.Error
	}
	return collections, nil
}

// DeleteGroup deletes a group and cleans up any collection ACL entries that reference the
// group's name (ACLs store group names, not group slugs).
//
// Only the group owner or a system admin may delete the group.
func DeleteGroup(db *gorm.DB, groupID, requestorUserID string, isAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Fetch group inside transaction to avoid race conditions
		var group Group
		if err := tx.First(&group, "id = ?", groupID).Error; err != nil {
			return err
		}

		if !isGroupOwnerOnly(&group, requestorUserID, isAdmin) {
			return ErrForbidden
		}

		// Remove any invite links referencing the group.
		if err := tx.Where("group_id = ?", group.ID).Delete(&GroupInviteLink{}).Error; err != nil {
			return err
		}

		// Remove any ACL entries referencing the group name.
		if err := tx.Where("group_id = ?", group.Name).Delete(&CollectionACL{}).Error; err != nil {
			return err
		}

		// Delete group members explicitly (in addition to any FK cascade).
		if err := tx.Where("group_id = ?", group.ID).Delete(&GroupMember{}).Error; err != nil {
			return err
		}

		// Finally, delete the group itself.
		if err := tx.Delete(&group).Error; err != nil {
			return err
		}

		return nil
	})
}

// DeleteUser deletes a user and cleans up any collection ACL entries that reference the
// user's implicit personal group name ("user-"+username).
//
// If isAdmin is false, only the user themselves may delete their account.
func DeleteUser(db *gorm.DB, userID, requestorUserID string, isAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Fetch user inside transaction to avoid race conditions
		var user User
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			return err
		}

		if !isAdmin && user.ID != requestorUserID {
			return ErrForbidden
		}

		personalGroup := "user-" + user.Username

		// Remove any ACL entries referencing the user's personal group name.
		if err := tx.Where("group_id = ?", personalGroup).Delete(&CollectionACL{}).Error; err != nil {
			return err
		}

		// Delete group memberships explicitly (in addition to any FK cascade).
		if err := tx.Where("user_id = ?", user.ID).Delete(&GroupMember{}).Error; err != nil {
			return err
		}

		// Finally, delete the user itself.
		if err := tx.Delete(&user).Error; err != nil {
			return err
		}

		return nil
	})
}

// --- Group Invite Link CRUD ---

// generateInviteToken creates a cryptographically random token for invite links.
// Returns (plaintext_token, token_id_prefix, error).
func generateInviteToken() (string, string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	plaintext := hex.EncodeToString(tokenBytes)
	// Use first 8 chars of SHA256 as a short identifier
	hash := sha256.Sum256(tokenBytes)
	prefix := hex.EncodeToString(hash[:])[:8]
	return plaintext, prefix, nil
}

// hashInviteToken returns a bcrypt hash of the plaintext token for secure storage.
func hashInviteToken(plaintext string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// CreateGroupInviteLink creates a new invite link for a group. Only the group owner or admin
// (or a system admin) may create invite links.
// Returns (inviteLink, plaintextToken, error). The plaintext token is returned only once and not stored.
func CreateGroupInviteLink(db *gorm.DB, groupID, createdByUserID string, expiresAt time.Time, isSingleUse bool, isSystemAdmin bool) (*GroupInviteLink, string, error) {
	var group Group
	if err := db.First(&group, "id = ?", groupID).Error; err != nil {
		return nil, "", err
	}

	if !isGroupOwnerOrAdmin(db, &group, createdByUserID, isSystemAdmin) {
		return nil, "", ErrForbidden
	}

	slug, err := generateSlug()
	if err != nil {
		return nil, "", err
	}

	plaintext, _, err := generateInviteToken()
	if err != nil {
		return nil, "", err
	}

	hashed, err := hashInviteToken(plaintext)
	if err != nil {
		return nil, "", err
	}

	link := &GroupInviteLink{
		ID:          slug,
		GroupID:     groupID,
		HashedToken: hashed,
		CreatedBy:   createdByUserID,
		ExpiresAt:   expiresAt,
		IsSingleUse: isSingleUse,
	}

	if result := db.Create(link); result.Error != nil {
		return nil, "", result.Error
	}

	return link, plaintext, nil
}

// CreateUserOnboardingInviteLink creates an invite link that onboards users
// without adding them to a group. Only system admins or user administrators can create these.
// Returns (inviteLink, plaintextToken, error).
func CreateUserOnboardingInviteLink(db *gorm.DB, createdByUserID string, expiresAt time.Time, isSingleUse bool) (*GroupInviteLink, string, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, "", err
	}

	plaintext, _, err := generateInviteToken()
	if err != nil {
		return nil, "", err
	}

	hashed, err := hashInviteToken(plaintext)
	if err != nil {
		return nil, "", err
	}

	link := &GroupInviteLink{
		ID:          slug,
		GroupID:     "", // empty = user-onboarding only, no group
		HashedToken: hashed,
		CreatedBy:   createdByUserID,
		ExpiresAt:   expiresAt,
		IsSingleUse: isSingleUse,
	}

	if result := db.Create(link); result.Error != nil {
		return nil, "", result.Error
	}

	return link, plaintext, nil
}

// ListGroupInviteLinks returns all invite links for a given group.
func ListGroupInviteLinks(db *gorm.DB, groupID string) ([]GroupInviteLink, error) {
	var links []GroupInviteLink
	if err := db.Where("group_id = ?", groupID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// GetGroupInviteLinkByToken looks up an invite link by scanning all non-revoked,
// non-expired links and comparing the bcrypt hash. Returns nil if not found.
func GetGroupInviteLinkByToken(db *gorm.DB, plaintext string) (*GroupInviteLink, error) {
	var links []GroupInviteLink
	if err := db.Where("revoked = 0 AND expires_at > ?", time.Now()).Find(&links).Error; err != nil {
		return nil, err
	}
	for i := range links {
		if err := bcrypt.CompareHashAndPassword([]byte(links[i].HashedToken), []byte(plaintext)); err == nil {
			return &links[i], nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

// RedeemGroupInviteLink redeems an invite link, adding the user to the group.
// It validates the link is not expired, not revoked, and (if single-use) not already redeemed.
func RedeemGroupInviteLink(db *gorm.DB, plaintext string, userID string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Scan non-revoked, non-expired links and bcrypt-compare
		var links []GroupInviteLink
		if err := tx.Where("revoked = 0 AND expires_at > ?", time.Now()).Find(&links).Error; err != nil {
			return err
		}
		var link *GroupInviteLink
		for i := range links {
			if err := bcrypt.CompareHashAndPassword([]byte(links[i].HashedToken), []byte(plaintext)); err == nil {
				link = &links[i]
				break
			}
		}
		if link == nil {
			return gorm.ErrRecordNotFound
		}

		if link.Revoked {
			return errors.New("invite link has been revoked")
		}

		if time.Now().After(link.ExpiresAt) {
			return errors.New("invite link has expired")
		}

		if link.IsSingleUse && link.RedeemedBy != "" {
			return errors.New("invite link has already been redeemed")
		}

		// Verify the user exists
		var user User
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errors.New("user does not exist")
			}
			return err
		}

		// If the link has a group, add the user to that group
		if link.GroupID != "" {
			groupMember := &GroupMember{
				GroupID: link.GroupID,
				UserID:  userID,
				AddedBy: link.CreatedBy,
			}
			if result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(groupMember); result.Error != nil {
				return result.Error
			}
		}
		// If GroupID is empty, this is a user-onboarding invite; no group addition needed.

		// Mark the link as redeemed
		now := time.Now()
		if err := tx.Model(&link).Updates(map[string]interface{}{
			"redeemed_by": userID,
			"redeemed_at": now,
		}).Error; err != nil {
			return err
		}

		return nil
	})
}

// RevokeGroupInviteLink revokes an invite link. Only the group owner or admin
// (or a system admin) may revoke invite links.
func RevokeGroupInviteLink(db *gorm.DB, linkID, requestorUserID string, isSystemAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var link GroupInviteLink
		if err := tx.First(&link, "id = ?", linkID).Error; err != nil {
			return err
		}

		var group Group
		if err := tx.First(&group, "id = ?", link.GroupID).Error; err != nil {
			return err
		}

		if !isGroupOwnerOrAdmin(tx, &group, requestorUserID, isSystemAdmin) {
			return ErrForbidden
		}

		return tx.Model(&link).Update("revoked", true).Error
	})
}

// --- User Status and AUP ---

// UpdateUserStatus updates the status (active/inactive) of a user.
func UpdateUserStatus(db *gorm.DB, userID string, status UserStatus) error {
	return db.Model(&User{}).Where("id = ?", userID).Update("status", status).Error
}

// UpdateUserLastLogin updates the last login timestamp of a user.
func UpdateUserLastLogin(db *gorm.DB, userID string) error {
	return db.Model(&User{}).Where("id = ?", userID).Update("last_login_at", time.Now()).Error
}

// UpdateUserDisplayName updates the display name of a user.
func UpdateUserDisplayName(db *gorm.DB, userID string, displayName string) error {
	return db.Model(&User{}).Where("id = ?", userID).Update("display_name", displayName).Error
}

// RecordAUPAgreement records that a user agreed to a specific version of the AUP.
func RecordAUPAgreement(db *gorm.DB, userID string, version string) error {
	now := time.Now()
	return db.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"aup_version":  version,
		"aup_agreed_at": now,
	}).Error
}

// --- User Identity CRUD ---

// CreateUserIdentity associates a new identity (sub + issuer) with an existing user.
func CreateUserIdentity(db *gorm.DB, userID, sub, issuer string) (*UserIdentity, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	identity := &UserIdentity{
		ID:     slug,
		UserID: userID,
		Sub:    sub,
		Issuer: issuer,
	}

	if result := db.Create(identity); result.Error != nil {
		if strings.Contains(result.Error.Error(), "UNIQUE constraint failed") {
			return nil, errors.New("identity (sub, issuer) is already associated with a user")
		}
		return nil, result.Error
	}

	return identity, nil
}

// ListUserIdentities returns all identities for a given user.
func ListUserIdentities(db *gorm.DB, userID string) ([]UserIdentity, error) {
	var identities []UserIdentity
	if err := db.Where("user_id = ?", userID).Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// DeleteUserIdentity removes a specific identity from a user.
func DeleteUserIdentity(db *gorm.DB, identityID, userID string) error {
	result := db.Where("id = ? AND user_id = ?", identityID, userID).Delete(&UserIdentity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("identity not found or does not belong to the user")
	}
	return nil
}

// GetUserByIdentity looks up a user by an identity (sub + issuer), checking both
// the primary user table and the user_identities table.
func GetUserByIdentity(db *gorm.DB, sub, issuer string) (*User, error) {
	// First check the primary user table
	user := &User{}
	err := db.Where("sub = ? AND issuer = ?", sub, issuer).First(user).Error
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// Check the user_identities table
	var identity UserIdentity
	if err := db.Where("sub = ? AND issuer = ?", sub, issuer).First(&identity).Error; err != nil {
		return nil, err
	}

	// Found via identity, look up the user
	if err := db.First(user, "id = ?", identity.UserID).Error; err != nil {
		return nil, err
	}
	return user, nil
}
