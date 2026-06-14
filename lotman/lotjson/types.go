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

package lotjson

import "encoding/json"

// BytesInGigabyte is the decimal-GB factor the lotman JSON schema has always
// used to convert between its GB sizes and the core's int64 bytes.
const BytesInGigabyte = 1000 * 1000 * 1000

type (
	Int64FromFloat struct {
		Value int64 `mapstructure:"Value"`
	}

	LotPath struct {
		Path      string `json:"path" mapstructure:"Path"`
		Recursive bool   `json:"recursive" mapstructure:"Recursive"`
		LotName   string `json:"lot_name,omitempty"` // Not used when creating lots, but some queries will populate the field
	}

	LotValueMapInt struct {
		LotName string         `json:"lot_name"`
		Value   Int64FromFloat `json:"value"`
	}

	LotValueMapFloat struct {
		LotName string  `json:"lot_name"`
		Value   float64 `json:"value"`
	}

	MPA struct {
		DedicatedGB     *float64        `json:"dedicated_GB,omitempty" mapstructure:"DedicatedGB"`
		OpportunisticGB *float64        `json:"opportunistic_GB,omitempty" mapstructure:"OpportunisticGB"`
		MaxNumObjects   *Int64FromFloat `json:"max_num_objects,omitempty" mapstructure:"MaxNumObjects"`
		CreationTime    *Int64FromFloat `json:"creation_time,omitempty" mapstructure:"CreationTime"`
		ExpirationTime  *Int64FromFloat `json:"expiration_time,omitempty" mapstructure:"ExpirationTime"`
		DeletionTime    *Int64FromFloat `json:"deletion_time,omitempty" mapstructure:"DeletionTime"`
	}

	// ParentAttribution describes how much of a parent lot's MPA budget is
	// attributed to a particular child lot. It is the per-axis carve-out
	// of the parent's quota that the child is permitted to consume. Used
	// in lotman's strict_hierarchy mode to enforce that the sum of
	// children's attributed quotas (with sweep-line over overlapping
	// active intervals) never exceeds the parent's MPA.
	ParentAttribution struct {
		DedicatedGB     *float64        `json:"dedicated_GB,omitempty" mapstructure:"DedicatedGB"`
		OpportunisticGB *float64        `json:"opportunistic_GB,omitempty" mapstructure:"OpportunisticGB"`
		MaxNumObjects   *Int64FromFloat `json:"max_num_objects,omitempty" mapstructure:"MaxNumObjects"`
	}

	// AvailableCapacity is the JSON document returned by
	// lotman_get_available_capacity. All sizes are in GB; counts are int64.
	AvailableCapacity struct {
		AvailableDedicatedGB     float64 `json:"available_dedicated_GB"`
		AvailableOpportunisticGB float64 `json:"available_opportunistic_GB"`
		AvailableMaxNumObjects   int64   `json:"available_max_num_objects"`
		AvailableTotalGB         float64 `json:"available_total_GB"`
		PeakDedicatedGB          float64 `json:"peak_dedicated_GB"`
		PeakOpportunisticGB      float64 `json:"peak_opportunistic_GB"`
		PeakMaxNumObjects        int64   `json:"peak_max_num_objects"`
		PeakTotalGB              float64 `json:"peak_total_GB"`
	}

	// PolicyAttrsRequest is the input JSON to lotman_get_policy_attributes.
	// Each bool selects whether that attribute should be present in the output.
	PolicyAttrsRequest struct {
		LotName         string `json:"lot_name"`
		DedicatedGB     bool   `json:"dedicated_GB,omitempty"`
		OpportunisticGB bool   `json:"opportunistic_GB,omitempty"`
		MaxNumObjects   bool   `json:"max_num_objects,omitempty"`
		CreationTime    bool   `json:"creation_time,omitempty"`
		ExpirationTime  bool   `json:"expiration_time,omitempty"`
		DeletionTime    bool   `json:"deletion_time,omitempty"`
	}

	// UsageRequest is the input JSON to lotman_get_lot_usage. Each bool
	// selects whether that usage axis should be reported and whether
	// children's contributions roll up into the result for that axis.
	UsageRequest struct {
		LotName             string `json:"lot_name"`
		DedicatedGB         *bool  `json:"dedicated_GB,omitempty"`
		OpportunisticGB     *bool  `json:"opportunistic_GB,omitempty"`
		TotalGB             *bool  `json:"total_GB,omitempty"`
		NumObjects          *bool  `json:"num_objects,omitempty"`
		GBBeingWritten      *bool  `json:"GB_being_written,omitempty"`
		ObjectsBeingWritten *bool  `json:"objects_being_written,omitempty"`
	}

	RestrictiveMPA struct {
		DedicatedGB     LotValueMapFloat `json:"dedicated_GB"`
		OpportunisticGB LotValueMapFloat `json:"opportunistic_GB"`
		MaxNumObjects   LotValueMapInt   `json:"max_num_objects"`
		CreationTime    LotValueMapInt   `json:"creation_time"`
		ExpirationTime  LotValueMapInt   `json:"expiration_time"`
		DeletionTime    LotValueMapInt   `json:"deletion_time"`
	}

	UsageMapFloat struct {
		SelfContrib     float64 `json:"self_contrib,omitempty"`
		ChildrenContrib float64 `json:"children_contrib,omitempty"`
		Total           float64 `json:"total"`
	}

	UsageMapInt struct {
		SelfContrib     Int64FromFloat `json:"self_contrib,omitempty"`
		ChildrenContrib Int64FromFloat `json:"children_contrib,omitempty"`
		Total           Int64FromFloat `json:"total"`
	}

	LotUsage struct {
		GBBeingWritten      UsageMapFloat `json:"GB_being_written,omitempty"`
		ObjectsBeingWritten UsageMapInt   `json:"objects_being_written,omitempty"`
		DedicatedGB         UsageMapFloat `json:"dedicated_GB,omitempty"`
		OpportunisticGB     UsageMapFloat `json:"opportunistic_GB,omitempty"`
		NumObjects          UsageMapInt   `json:"num_objects,omitempty"`
		TotalGB             UsageMapFloat `json:"total_GB,omitempty"`
	}

	Lot struct {
		LotName string `json:"lot_name" mapstructure:"LotName"`
		Owner   string `json:"owner,omitempty" mapstructure:"Owner"`
		// We don't expose Owners via map structure because that's not something we can configure. It's a derived value
		Owners  []string `json:"owners,omitempty"`
		Parents []string `json:"parents" mapstructure:"Parents"`
		// While we _could_ expose Children, that complicates things so for now we keep it hidden from the config
		Children *[]string `json:"children,omitempty"`
		Paths    []LotPath `json:"paths,omitempty" mapstructure:"Paths"`
		MPA      *MPA      `json:"management_policy_attrs,omitempty" mapstructure:"ManagementPolicyAttrs"`
		// ParentAttributions records how much of each parent lot's MPA budget
		// is reserved for this lot. Required (along with strict_hierarchy +
		// contraction_policy) by lotman's reservation enforcement.
		ParentAttributions map[string]ParentAttribution `json:"parent_attributions,omitempty" mapstructure:"ParentAttributions"`
		// Again, these are derived
		RestrictiveMPA *RestrictiveMPA `json:"restrictive_management_policy_attrs,omitempty"`
		Usage          *LotUsage       `json:"usage,omitempty"`
	}

	ParentUpdate struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}

	PathUpdate struct {
		Current   string `json:"current"`
		New       string `json:"new"`
		Recursive bool   `json:"recursive"`
	}

	LotUpdate struct {
		LotName            string                       `json:"lot_name"`
		Owner              *string                      `json:"owner,omitempty"`
		Parents            *[]ParentUpdate              `json:"parents,omitempty"`
		Paths              *[]PathUpdate                `json:"paths,omitempty"`
		MPA                *MPA                         `json:"management_policy_attrs,omitempty"`
		ParentAttributions map[string]ParentAttribution `json:"parent_attributions,omitempty"`
	}

	LotAddition struct {
		LotName            string                       `json:"lot_name"`
		Parents            []string                     `json:"parents,omitempty"`
		Paths              []LotPath                    `json:"paths,omitempty"`
		ParentAttributions map[string]ParentAttribution `json:"parent_attributions,omitempty"`
	}

	LotPathRemoval struct {
		// Paths can belong to at most one lot, so no need
		// to provide a lot name here
		Paths []string `json:"paths"`
	}

	LotParentRemoval struct {
		LotName string   `json:"lot_name"`
		Parents []string `json:"parents"`
	}
)

// Lotman has a tendency to return an int as 123.0 instead of 123. This struct is used to unmarshal
// those values into an int64
func (i *Int64FromFloat) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	i.Value = int64(f)
	return nil
}

func (i Int64FromFloat) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.Value)
}

// ExpirationTimeIsSentinel reports whether the lot uses the "non-expiring"
// all-zero timestamp sentinel (lotman PR #44). Sentinel lots (root,
// default) must never be extended by the renewal scheduler.
func (l Lot) ExpirationTimeIsSentinel() bool {
	if l.MPA == nil {
		return true
	}
	if l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil || l.MPA.DeletionTime == nil {
		return false
	}
	return l.MPA.CreationTime.Value == 0 &&
		l.MPA.ExpirationTime.Value == 0 &&
		l.MPA.DeletionTime.Value == 0
}
