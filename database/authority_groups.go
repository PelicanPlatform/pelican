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
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// EnsureConfiguredAuthorityGroups records a Pelican group for every
// name the operator has listed in Server.AdminGroups,
// Server.UserAdminGroups or Server.CollectionAdminGroups, so that the
// names which confer server-wide authority are held by this server
// before anyone can ask for them.
//
// Why this is a security fix and not just tidiness: group creation is
// open to any authenticated user, and a non-admin creator gets
// auth_template_eligible == false. FilterAuthTemplateEligibleGroups is
// keyed on the NAME, and it is global — one ineligible row named
// "ops" strips "ops" from every caller's group list, not just from the
// creator's. So on a server configured with
//
//	Server.AdminGroups: [ops]
//
// any user could create a group called "ops" and thereby revoke
// server.admin from every administrator who holds it through the
// issuer's "ops" assertion. Minting the record up front closes that:
// CreateGroup refuses a name that is already taken, and the record we
// mint is admin-owned and eligible, so the configured name keeps
// matching.
//
// This runs regardless of Issuer.DisableGroupAutoCreation. That knob
// governs names this server merely *observes* from a provider; these
// names are ones the operator typed into the config file. Disabling
// auto-creation is also precisely the case where nothing else would
// ever reserve them, so honoring the knob here would remove the
// protection exactly where it is needed most.
//
// `source` should be the configured group source (see
// web_ui.ConfiguredGroupSource). Recording the group under the source
// that will assert its memberships is what lets those memberships
// mirror into it normally; see MirrorAssertedGroupMemberships, which
// declines to mirror into a Pelican-created group. When no source is
// configured, GroupSourceUnknown is the right stamp — the first real
// assertion then completes the record rather than colliding with it.
//
// An error is returned only for a genuine database failure; a name
// that cannot be recorded is logged and skipped, because a single bad
// config entry must not stop the server from starting.
func EnsureConfiguredAuthorityGroups(db *gorm.DB, source GroupSource, names []string) error {
	if db == nil {
		return nil
	}
	if source == "" {
		// No provider configured (yet). Stamping the record `unknown`
		// rather than `pelican` matters: a Pelican-created group is one
		// this server owns the membership of, and
		// MirrorAssertedGroupMemberships refuses to mirror into it. An
		// `unknown` record is instead *completed* by the first real
		// assertion, so configuring Issuer.GroupSource later works
		// without the reservation getting in the way.
		source = GroupSourceUnknown
	}
	wanted := recordableGroupNames(names, "listed in a Server.*AdminGroups config entry")
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
			// think, but never take the name over: seizing a group out
			// from under its owner, or flipping eligibility on a group
			// this server did not create, would hand its members the
			// very authority the operator is trying to control.
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
			Source:               source,
		}
		if err := db.Create(grp).Error; err != nil {
			if isUniqueConstraintError(err) {
				// Raced with another writer for the same name; the
				// name is held, which is all we wanted.
				continue
			}
			return err
		}
		log.Infof("Reserved group %q from the Server.*AdminGroups configuration as group ID %s (source %s)",
			name, slug, source)
	}
	return nil
}

// recordableGroupNames trims and de-duplicates `names`, dropping the
// ones this server must not mint a group record for. `origin`
// describes where the names came from and appears in the log line
// explaining each skip.
//
// Deliberately NOT ValidateIdentifier: that validator governs what a
// *user* may name a group they create, and it bans `/` because a
// self-chosen name can end up as a path component in an authz
// template. The names here are either asserted by a provider or typed
// by the operator, and WLCG-style providers routinely assert
// `/cms/production` — refusing those would leave exactly the groups an
// operator most wants to ACL without an ID.
//
// Two shapes are still excluded, because a record under either would
// be indistinguishable from this server's own presentation forms for a
// NAME-space ACL target: the `user-` personal prefix and the `@`
// sentinel namespace. Such a name keeps working for auth-template
// matching; it just doesn't get a record. An ID-shaped name is fine —
// nothing resolves a name by its shape, so it cannot be mistaken for
// an ID.
func recordableGroupNames(names []string, origin string) []string {
	if len(names) == 0 {
		return nil
	}
	wanted := make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if slices.Contains(wanted, name) {
			continue
		}
		if strings.HasPrefix(name, PersonalACLGroupPrefix) || strings.HasPrefix(name, "@") {
			log.Debugf("Not recording group %q (%s): the name collides with a reserved ACL-target form", name, origin)
			continue
		}
		if len(name) > maxAssertedGroupNameLen {
			log.Debugf("Not recording group %q (%s): name exceeds %d bytes", name, origin, maxAssertedGroupNameLen)
			continue
		}
		wanted = append(wanted, name)
	}
	return wanted
}
