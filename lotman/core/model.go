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

package core

// The GORM models below map 1:1 onto the tables created by the embedded Goose
// migrations (see migrations/). Goose is authoritative for the schema; these
// structs are the typed access layer. All times are Unix milliseconds.

// Lot is the central record: a named accounting unit with an owner, a lifecycle
// window, and management-policy attributes (MPAs). Owner and the MPA columns are
// folded into this table (1:1 with the lot) rather than kept in separate tables.
type Lot struct {
	LotName            string `gorm:"column:lot_name;primaryKey"`
	Owner              string `gorm:"column:owner;not null"`
	DedicatedBytes     int64  `gorm:"column:dedicated_bytes;not null;default:0"`
	OpportunisticBytes int64  `gorm:"column:opportunistic_bytes;not null;default:0"`
	MaxNumObjects      int64  `gorm:"column:max_num_objects;not null;default:0"`
	CreationTime       int64  `gorm:"column:creation_time;not null;default:0"`
	ExpirationTime     int64  `gorm:"column:expiration_time;not null;default:0"`
	DeletionTime       int64  `gorm:"column:deletion_time;not null;default:0"`
	CreatedAt          int64  `gorm:"column:created_at;not null;default:0"`
	UpdatedAt          int64  `gorm:"column:updated_at;not null;default:0"`
}

func (Lot) TableName() string { return "lots" }

// LotParent is a single DAG edge from a lot to one of its parents. A root lot
// has an edge to itself.
type LotParent struct {
	LotName string `gorm:"column:lot_name;primaryKey"`
	Parent  string `gorm:"column:parent;primaryKey"`
}

func (LotParent) TableName() string { return "lot_parents" }

// LotPath associates a filesystem/object path prefix with a lot. Recursive
// controls whether subdirectories belong to the lot; Exclude marks a path that
// is ignored by resolution (an escape hatch).
type LotPath struct {
	LotName   string `gorm:"column:lot_name;primaryKey"`
	Path      string `gorm:"column:path;primaryKey"`
	Recursive bool   `gorm:"column:recursive;not null;default:false"`
	Exclude   bool   `gorm:"column:exclude;not null;default:false"`
}

func (LotPath) TableName() string { return "lot_paths" }

// LotUsage tracks per-lot usage, keeping self and children contributions
// separate so callers can choose whether to count descendants toward a quota.
type LotUsage struct {
	LotName                     string `gorm:"column:lot_name;primaryKey"`
	SelfBytes                   int64  `gorm:"column:self_bytes;not null;default:0"`
	ChildrenBytes               int64  `gorm:"column:children_bytes;not null;default:0"`
	SelfObjects                 int64  `gorm:"column:self_objects;not null;default:0"`
	ChildrenObjects             int64  `gorm:"column:children_objects;not null;default:0"`
	SelfBytesBeingWritten       int64  `gorm:"column:self_bytes_being_written;not null;default:0"`
	ChildrenBytesBeingWritten   int64  `gorm:"column:children_bytes_being_written;not null;default:0"`
	SelfObjectsBeingWritten     int64  `gorm:"column:self_objects_being_written;not null;default:0"`
	ChildrenObjectsBeingWritten int64  `gorm:"column:children_objects_being_written;not null;default:0"`
}

func (LotUsage) TableName() string { return "lot_usage" }

// MPA-key constants used by LotParentAttribution.MpaKey.
const (
	MpaKeyDedicatedBytes     = "dedicated_bytes"
	MpaKeyOpportunisticBytes = "opportunistic_bytes"
	MpaKeyMaxNumObjects      = "max_num_objects"
)

// LotParentAttribution records, under strict hierarchy, the absolute amount of
// a child's MPA on a given axis that is attributed to a particular parent
// (bytes for the storage axes, a count for objects; -1 means unbounded).
type LotParentAttribution struct {
	ChildLotName    string `gorm:"column:child_lot_name;primaryKey"`
	ParentLotName   string `gorm:"column:parent_lot_name;primaryKey"`
	MpaKey          string `gorm:"column:mpa_key;primaryKey"`
	AttributedValue int64  `gorm:"column:attributed_value;not null"`
}

func (LotParentAttribution) TableName() string { return "lot_parent_attributions" }

// LotReclamation is a ledger entry marking a lot (and, by cascade in the
// application logic, its descendants) as released by the storage provider.
type LotReclamation struct {
	LotName         string `gorm:"column:lot_name;primaryKey"`
	ReclaimedAt     int64  `gorm:"column:reclaimed_at;not null"`
	ReclaimedReason string `gorm:"column:reclaimed_reason"`
}

func (LotReclamation) TableName() string { return "lot_reclamations" }
