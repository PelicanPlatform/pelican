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

import (
	"fmt"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
)

// EnsureConfiguredAuthorityGroups records a Pelican group for every
// name the operator has listed in Server.AdminGroups,
// Server.UserAdminGroups or Server.CollectionAdminGroups, so that the
// names which confer server-wide authority are held by this server
// before anyone can ask for them.
//
// Group creation is open to any authenticated user, and a non-admin
// creator gets auth_template_eligible == false.
// So on a server configured with
//
//	Server.AdminGroups: [ops]
//
// where an `ops` group didn't pre-exist, any user could create a group
// called "ops" and thereby revoke server.admin from every administrator
// who holds it through the issuer's "ops" assertion. Minting the record
// up front closes that: CreateGroup refuses a name that is already taken.
//
// This runs regardless of Issuer.DisableGroupAutoCreation. That knob
// governs names this server merely *observes* from a provider; these
// names are ones the operator typed into the config file.
//
// Records are always stamped GroupSourceUnknown; see the Group literal
// below for why.
//
// A configured name this server cannot reserve fails startup rather
// than being skipped.
//
// A name a PROVIDER asserts is still only filtered, never fatal — see
// partitionRecordableGroupNames.
func EnsureConfiguredAuthorityGroups(db *gorm.DB, names []string) error {
	if db == nil {
		return nil
	}
	// Validate before doing anything. These names were typed by the
	// operator, so an entry this server can never honor is a mistake to
	// report, not input to filter — see partitionRecordableGroupNames.
	wanted, rejected := partitionRecordableGroupNames(names)
	if len(rejected) > 0 {
		reasons := make([]string, 0, len(rejected))
		for _, r := range rejected {
			reasons = append(reasons, fmt.Sprintf("%q %s", r.Name, r.Reason))
		}
		return fmt.Errorf("Server.*AdminGroups names a group this server cannot reserve: %s. "+
			"Such a name still matches an assertion carrying it, but has no record to hold it and no "+
			"auth_template_eligible bit to revoke it with", strings.Join(reasons, "; "))
	}
	if len(wanted) == 0 {
		return nil
	}

	var existing []Group
	if err := db.Select("id", "name", "source", "auth_template_eligible").
		Where("name IN ? AND deleted_at IS NULL", wanted).Find(&existing).Error; err != nil {
		return err
	}
	known := make(map[string]Group, len(existing))
	for _, g := range existing {
		known[g.Name] = g
	}

	var adminID, createdBy string
	if len(known) < len(wanted) {
		admin, err := BuiltinAdminUser(db)
		if err != nil {
			return err
		}
		if admin != nil {
			adminID = admin.ID
			createdBy = admin.ID
		} else {
			// Brand-new install, admin row not written yet. Leave the
			// group ownerless; BootstrapAdminAndBackfillOwners adopts
			// every ownerless group on the next startup.
			createdBy = CreatorUnknown
		}
	}

	for _, name := range wanted {
		if g, ok := known[name]; ok {
			// The name is already held. Report the cases where that
			// means the operator's config entry is not doing what they
			// think, but never take the name over.
			if !g.AuthTemplateEligible {
				log.Errorf("Group %q is listed in a Server.*AdminGroups config entry, but an existing group with "+
					"that name (id %s, source %s) is not eligible for authorization templates, so the config entry "+
					"currently grants nothing. Resolve the collision by renaming or removing that group.", name, g.ID, g.Source)
			} else if g.Source == GroupSourcePelican {
				log.Infof("Group %q, listed in a Server.*AdminGroups config entry, already exists as a "+
					"Pelican-managed group (id %s); its membership is managed locally", name, g.ID)
			}
			continue
		}
		slug, err := generateSlug()
		if err != nil {
			return err
		}
		grp := &Group{
			ID:                   slug,
			Name:                 name,
			CreatedBy:            createdBy,
			OwnerID:              adminID,
			AuthTemplateEligible: true,
			// Always GroupSourceUnknown. This server has not observed
			// the name from any provider — it is reserving a name an
			// operator typed — so stamping the configured source would
			// be inventing provenance. `unknown` says exactly what is
			// true: some provider is expected to assert this name, and
			// which one is not yet known. The first real assertion
			// completes the record (see EnsureAssertedGroups).
			//
			// It also has to be a source that IsAsserted(), or the
			// reservation would not do its job: CreateGroup only turns
			// a name clash into ErrGroupNameConflict for an asserted
			// group, and MirrorAssertedGroupMemberships declines to
			// mirror into a `pelican` one. Stamping the configured
			// source would make both of those wrong whenever
			// Issuer.GroupSource is `internal`, which maps to
			// GroupSourcePelican.
			Source: GroupSourceUnknown,
		}
		if err := db.Create(grp).Error; err != nil {
			if isUniqueConstraintError(err) {
				// Raced with another writer for the same name; the
				// name is held, which is all we wanted.
				continue
			}
			return err
		}
		log.Infof("Reserved group %q from the Server.*AdminGroups configuration as group ID %s", name, slug)
	}
	return nil
}

// groupNameRejection is one name this server will not mint a group
// record for, with a reason phrased for an operator to act on.
type groupNameRejection struct {
	Name   string
	Reason string
}

// partitionRecordableGroupNames trims and de-duplicates `names` and
// splits them into the ones this server can mint a group record for and
// the ones it cannot. It is the single place the rules live, so the two
// callers cannot drift apart while treating the result differently:
// a provider's assertion is FILTERED (see recordableGroupNames), while
// an operator's configuration is REJECTED — a name a human typed that
// can never be honored is a mistake to report, not input to drop.
//
// Deliberately NOT ValidateIdentifier: that validator governs what a
// *user* may name a group they create, and it bans `/` because a
// self-chosen name can end up as a path component in an authz template.
// The names here are either asserted by a provider or typed by the
// operator, and WLCG-style providers routinely assert `/cms/production`
// — refusing those would leave exactly the groups an operator most
// wants to ACL without an ID.
//
// Two shapes are still excluded, because a record under either would be
// indistinguishable from this server's own presentation forms for a
// NAME-space ACL target: the `user-` personal prefix and the `@`
// sentinel namespace. An ID-shaped name is fine — nothing resolves a
// name by its shape, so it cannot be mistaken for an ID.
//
// Blank and repeated entries are dropped silently rather than rejected:
// neither can grant anything, so neither is worth failing a startup
// over.
func partitionRecordableGroupNames(names []string) (recordable []string, rejected []groupNameRejection) {
	if len(names) == 0 {
		return nil, nil
	}
	recordable = make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" || slices.Contains(recordable, name) {
			continue
		}
		switch {
		case strings.HasPrefix(name, PersonalACLGroupPrefix):
			rejected = append(rejected, groupNameRejection{name,
				"starts with the reserved `" + PersonalACLGroupPrefix + "` prefix, which names a single user rather than a group"})
		case strings.HasPrefix(name, "@"):
			rejected = append(rejected, groupNameRejection{name,
				"starts with `@`, which is reserved for sentinel ACL targets such as " + AllAuthenticatedUsersACLGroup})
		case len(name) > maxAssertedGroupNameLen:
			rejected = append(rejected, groupNameRejection{name,
				fmt.Sprintf("exceeds the %d-byte limit for a group name", maxAssertedGroupNameLen)})
		default:
			recordable = append(recordable, name)
		}
	}
	return recordable, rejected
}

// recordableGroupNames is the FILTERING view of the rules above, for
// names a provider asserted. A provider may assert anything, and an
// unusable name it happens to carry must not fail the login that
// brought it — the name simply goes unrecorded. `origin` describes
// where the names came from and appears in the log line for each skip.
func recordableGroupNames(names []string, origin string) []string {
	recordable, rejected := partitionRecordableGroupNames(names)
	for _, r := range rejected {
		log.Debugf("Not recording group %q (%s): the name %s", r.Name, origin, r.Reason)
	}
	return recordable
}

// configuredAuthorityGroupNames returns every group name the operator
// has given server-wide authority to, across the three admin lists.
func configuredAuthorityGroupNames() []string {
	return slices.Concat(
		param.Server_AdminGroups.GetStringSlice(),
		param.Server_UserAdminGroups.GetStringSlice(),
		param.Server_CollectionAdminGroups.GetStringSlice(),
	)
}

// isConfiguredAuthorityGroupName reports whether `name` is one the
// configuration currently says confers an administrator scope. Compared
// exactly, the same way EffectiveScopesForIdentity matches them.
func isConfiguredAuthorityGroupName(name string) bool {
	for _, configured := range configuredAuthorityGroupNames() {
		if strings.TrimSpace(configured) == name {
			return true
		}
	}
	return false
}

// describeGroupNameHold explains, to an operator who just had a name
// refused, why it is unavailable.
//
// GroupSourceUnknown needs its own phrasing. Nothing has asserted such
// a record: it was either reserved from Server.*AdminGroups at startup
// (EnsureConfiguredAuthorityGroups) or backfilled by migration from an
// old name-keyed ACL. Reporting it as "asserted by the unknown group
// source" names a provider that was never involved and sends the reader
// looking for one.
func describeGroupNameHold(g *Group) string {
	if g.Source == GroupSourceUnknown {
		if isConfiguredAuthorityGroupName(g.Name) {
			return "is reserved because it confers administrator authority via Server.*AdminGroups"
		}
		return "is reserved for a provider-asserted group, though no provider has claimed it yet"
	}
	return fmt.Sprintf("is asserted by the %s group source", g.Source)
}
