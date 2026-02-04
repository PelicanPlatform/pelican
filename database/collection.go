package database

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

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

type User struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"not null;uniqueIndex:idx_user_issuer" json:"username"`
	Sub       string    `gorm:"not null;uniqueIndex:idx_user_sub_issuer" json:"sub"`
	Issuer    string    `gorm:"not null;uniqueIndex:idx_user_issuer;uniqueIndex:idx_user_sub_issuer" json:"issuer"`
	CreatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

type Group struct {
	ID          string        `gorm:"primaryKey" json:"id"`
	Name        string        `gorm:"not null;unique" json:"name"`
	Description string        `json:"description"`
	CreatedBy   string        `gorm:"not null" json:"createdBy"`
	CreatedAt   time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	Members     []GroupMember `gorm:"foreignKey:GroupID" json:"members"`
}

type GroupMember struct {
	GroupID string    `gorm:"primaryKey" json:"groupId"`
	UserID  string    `gorm:"primaryKey" json:"userId"`
	User    User      `gorm:"foreignKey:UserID" json:"user"`
	AddedBy string    `gorm:"not null" json:"createdBy"`
	AddedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
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

		if !isAdmin && group.CreatedBy != requestorUserID {
			return ErrForbidden
		}

		return tx.Model(&Group{}).Where("id = ?", id).Updates(updates).Error
	})
}

func AddGroupMember(db *gorm.DB, groupId, userId, addedByUserId string) error {
	var group Group
	if err := db.First(&group, "id = ?", groupId).Error; err != nil {
		return err
	}

	if group.CreatedBy != addedByUserId {
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

func RemoveGroupMember(db *gorm.DB, groupId, userId, removedByUserId string) error {
	var group Group
	if err := db.First(&group, "id = ?", groupId).Error; err != nil {
		return err
	}

	if group.CreatedBy != removedByUserId {
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
// If isAdmin is false, only the group creator (CreatedBy) may delete the group.
func DeleteGroup(db *gorm.DB, groupID, requestorUserID string, isAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Fetch group inside transaction to avoid race conditions
		var group Group
		if err := tx.First(&group, "id = ?", groupID).Error; err != nil {
			return err
		}

		if !isAdmin && group.CreatedBy != requestorUserID {
			return ErrForbidden
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
