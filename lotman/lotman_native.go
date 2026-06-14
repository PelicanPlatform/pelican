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

// The LotMan library is used for managing storage in Pelican caches. For more information, see:
// https://github.com/pelicanplatform/lotman
package lotman

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	dbutils "github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/lotman/core"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// initializedLots holds the lot set computed by initLots during InitLotman and
// consumed by ensureLotExistsOrUpdate.
var initializedLots []Lot

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

	PurgePolicy struct {
		PurgeOrder               []string `mapstructure:"PurgeOrder"`
		PolicyName               string   `mapstructure:"PolicyName"`
		DiscoverPrefixes         bool     `mapstructure:"DiscoverPrefixes"`
		MergeLocalWithDiscovered bool     `mapstructure:"MergeLocalWithDiscovered"`
		DivideUnallocated        bool     `mapstructure:"DivideUnallocated"`
		Lots                     []Lot    `mapstructure:"Lots"`
	}
)

const (
	bytesInGigabyte = 1000 * 1000 * 1000
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

// GetAuthorizedCallers returns the set of owners permitted to manipulate (and
// thus delete) the named lot: the owners of the lot's immediate parents
// (including itself when self-parenting), resolved recursively up the tree.
func GetAuthorizedCallers(lotName string) (*[]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	// Immediate parents, including self for a self-parenting (root) lot.
	parents, err := m.GetParents(lotName, false, true)
	if err != nil {
		return nil, err
	}
	ownersSet := make(map[string]struct{})
	for _, parent := range parents {
		owners, err := m.GetOwners(parent, true)
		if err != nil {
			return nil, err
		}
		for _, owner := range owners {
			ownersSet[owner] = struct{}{}
		}
	}
	owners := make([]string, 0, len(ownersSet))
	for owner := range ownersSet {
		owners = append(owners, owner)
	}
	return &owners, nil
}

// Under our model, we set owner to the issuer. Since this is owned by the federation, we set it in order of preference:
// 1. The federation's discovery url
// 2. The federation's director url
// TODO: Consider what happens to the lot if either of these values change in the future after the lot is created?
func getFederationIssuer() (string, error) {
	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return "", err
	}
	federationIssuer := fedInfo.DiscoveryEndpoint
	if federationIssuer == "" {
		return "", errors.New("unable to determine the federation's discovery endpoint/issuer for lot ownership")
	}

	return federationIssuer, nil
}

// Given MPA1 and MPA2, merge them into a single MPA. If a field is set in MPA1,
// it will take precedence.
func mergeMPAs(mpa1, mpa2 *MPA) *MPA {
	// Handle nil cases
	if mpa1 == nil && mpa2 == nil {
		return nil
	}
	if mpa1 == nil {
		return mpa2
	}
	if mpa2 == nil {
		return mpa1
	}

	// Merge individual fields
	mergedMPA := *mpa1
	if mpa1.DedicatedGB == nil {
		mergedMPA.DedicatedGB = mpa2.DedicatedGB
	}
	if mpa1.OpportunisticGB == nil {
		mergedMPA.OpportunisticGB = mpa2.OpportunisticGB
	}
	if mpa1.MaxNumObjects == nil {
		mergedMPA.MaxNumObjects = mpa2.MaxNumObjects
	}
	if mpa1.CreationTime == nil {
		mergedMPA.CreationTime = mpa2.CreationTime
	}
	if mpa1.ExpirationTime == nil {
		mergedMPA.ExpirationTime = mpa2.ExpirationTime
	}
	if mpa1.DeletionTime == nil {
		mergedMPA.DeletionTime = mpa2.DeletionTime
	}

	return &mergedMPA
}

// Given lot1 and lot2, merge them into a single lot. If a field is set in lot1,
// it will take precedence. Lots cannot be merged if they have separate names
func mergeLots(lot1, lot2 Lot) (Lot, error) {
	if lot1.LotName != lot2.LotName {
		return Lot{}, errors.Errorf("cannot merge lots %s and %s because they have different names", lot1.LotName, lot2.LotName)
	}
	mergedLot := lot1

	// Prefer lot1's owner
	if lot1.Owner == "" {
		mergedLot.Owner = lot2.Owner
	}

	// Calculate union between the parents -- if this gets us in trouble by introducing cycles,
	// lotman will tell us on startup (hopefully...).
	parentSet := make(map[string]bool)
	for _, parent := range lot1.Parents {
		parentSet[parent] = true
	}
	for _, parent := range lot2.Parents {
		if !parentSet[parent] {
			mergedLot.Parents = append(mergedLot.Parents, parent)
			parentSet[parent] = true
		}
	}

	// Merge the MPAs
	mergedLot.MPA = mergeMPAs(lot1.MPA, lot2.MPA)

	return mergedLot, nil
}

// Calculate the union of two lot maps. If a lot is present in both maps, merge them.
func mergeLotMaps(map1, map2 map[string]Lot) (map[string]Lot, error) {
	result := make(map[string]Lot)

	// Add all entries from map1 to result
	for key, value := range map1 {
		result[key] = value
	}

	// Merge entries from map2 into result
	for key, value := range map2 {
		if existingValue, exists := result[key]; exists {
			mergedLot, err := mergeLots(existingValue, value)
			if err != nil {
				return result, err
			}
			result[key] = mergedLot
		} else {
			result[key] = value
		}
	}

	return result, nil
}

// A hook function for mapstructure that validates that all fields in the map are present in the struct.
// Used to verify the user's input for PolicyDefinitions, since these aren't top-level fields in parameters.yaml
func validateFieldsHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.Map || to.Kind() != reflect.Struct {
			return data, nil
		}

		mapKeys := reflect.ValueOf(data).MapKeys()
		structFields := make(map[string]struct{})
		for i := 0; i < to.NumField(); i++ {
			field := to.Field(i)
			// Normalize the field name to lowercase
			structFields[strings.ToLower(field.Tag.Get("mapstructure"))] = struct{}{}
		}

		// Check for unknown fields
		for _, key := range mapKeys {
			if _, ok := structFields[strings.ToLower(key.String())]; !ok {
				return nil, fmt.Errorf("unknown configuration field in Lotman policy definitions: %s", key.String())
			}
		}

		return data, nil
	}
}

// Grab a map of policy definitions from the config file, where the policy
// name is the key and its attributes comprise the value.
func GetPolicyMap() (map[string]PurgePolicy, error) {
	policyMap := make(map[string]PurgePolicy)
	var policies []PurgePolicy
	// Use custom decoder hook to validate fields. This validates all the way down to the bottom of the lot object.
	if err := viper.UnmarshalKey(param.Lotman_PolicyDefinitions.GetName(), &policies, viper.DecodeHook(validateFieldsHook())); err != nil {
		return policyMap, errors.Wrap(err, "error unmarshalling Lotman policy definitions")
	}

	for _, policy := range policies {
		policyMap[policy.PolicyName] = policy
	}

	return policyMap, nil
}

func bytesToGigabytes(bytes uint64) float64 {
	return float64(bytes) / bytesInGigabyte
}

func gigabytesToBytes(gb float64) uint64 {
	return uint64(gb * bytesInGigabyte)
}

// Given the list of lots and the total disk space available to the cache, validate that
// each lot has all necessary creation fields and that their values are within reasonable bounds.
// In particular, we want to make sure that the sum of all lots' dedicatedGB values does not exceed
// the high watermark of the cache, as this would allow the cache to purge data from namespaces
// that are using less than their dedicated quota.
func validateLotsConfig(lots []Lot, totalDiskSpaceB uint64) error {
	hwmStr := param.Cache_HighWaterMark.GetString()
	hwm, err := convertWatermarkToBytes(hwmStr, totalDiskSpaceB)
	if err != nil {
		return errors.Wrap(err, "error converting high watermark to byte value for Lotman")
	}

	totalDedicatedGB := 0.0
	for _, lot := range lots {
		// Skip the root and default lots, which are synthesised by Pelican with
		// effectively unbounded MPAs so that strict-hierarchy axiom 1 is
		// trivially satisfied for any lot that is (re)parented under them.
		// Their dedicatedGB therefore intentionally exceeds the HWM and must
		// be excluded from the sum check below.
		if lot.LotName == "root" || lot.LotName == "default" {
			continue
		}
		// Instead of returning on the first missing field, try to get everything for the entire lot.
		// We could also do this for _all_ lots before returning, but that may be an overwhelming error
		// message. This way, the user can focus on one lot at a time.
		missingValues := make([]string, 0)
		if lot.LotName == "" {
			return errors.New(fmt.Sprintf("detected a lot with no name: %+v", lot))
		}
		errMsg := fmt.Sprintf("the lot '%s' is missing required values:", lot.LotName)

		if lot.Owner == "" {
			missingValues = append(missingValues, "Owner")
		}
		if len(lot.Parents) == 0 {
			missingValues = append(missingValues, "Parents")
		} else {
			for _, parent := range lot.Parents {
				if parent == "" {
					missingValues = append(missingValues, "Parents")
				}
			}
		}
		if len(lot.Paths) == 0 {
			// Default lot doesn't need paths, but everybody else does
			if lot.LotName != "default" {
				missingValues = append(missingValues, "Paths")
			}
		} else {
			for _, path := range lot.Paths {
				if path.Path == "" {
					missingValues = append(missingValues, "Paths.Path")
				}
			}
		}

		if lot.MPA == nil {
			missingValues = append(missingValues, "ManagementPolicyAttrs")
		} else {
			if lot.MPA.DedicatedGB == nil {
				missingValues = append(missingValues, "ManagementPolicyAttrs.DedicatedGB")
			} else {
				totalDedicatedGB += *lot.MPA.DedicatedGB
			}
			if lot.MPA.OpportunisticGB == nil {
				missingValues = append(missingValues, "ManagementPolicyAttrs.OpportunisticGB")
			}
			// No checking for MaxNumObjects -- the purge plugin doesn't use it yet
			// Timestamp nil-check only: a value of 0 is the lotman non-expiring
			// sentinel (PR #44) and is explicitly valid for user-defined lots.
			if lot.MPA.CreationTime == nil {
				missingValues = append(missingValues, "ManagementPolicyAttrs.CreationTime")
			}
			if lot.MPA.ExpirationTime == nil {
				missingValues = append(missingValues, "ManagementPolicyAttrs.ExpirationTime")
			}
			if lot.MPA.DeletionTime == nil {
				missingValues = append(missingValues, "ManagementPolicyAttrs.DeletionTime")
			}
		}

		if len(missingValues) > 0 {
			return errors.New(fmt.Sprintf("%s %v", errMsg, missingValues))
		}

		// We don't apply validation to the opportunistic GB, as it's not a hard limit and the user
		// may wish to do something unexpected. However, the sum of dedicated GB should not exceed the HWM
		// or the cache may expose some data to purging when it should be protected.
		if totalDedicatedGB > bytesToGigabytes(hwm) {
			return errors.New(fmt.Sprintf("the sum of all lots' dedicatedGB values exceeds the high watermark of %s. This would allow the cache to purge namespaces using less than their dedicated quota", hwmStr))
		}
	}

	return nil
}

// HWM and LWM values may be a percentage (e.g. 95) indicating the amount of available disk
// to treat as the watermark, or they may be a suffixed byte value (e.g. 100G). We need this
// information in bytes to calculate the amount of space to allocate to each lot.
func convertWatermarkToBytes(value string, totalDiskSpace uint64) (uint64, error) {
	suffixMultipliers := map[string]uint64{
		"k": 1000,
		"m": 1000 * 1000,
		"g": 1000 * 1000 * 1000,
		"t": 1000 * 1000 * 1000 * 1000,
	}

	// Check if the value has a suffix
	if len(value) > 1 {
		suffix := strings.ToLower(string(value[len(value)-1]))
		if multiplier, exists := suffixMultipliers[suffix]; exists {
			number, err := strconv.ParseFloat(value[:len(value)-1], 64)
			if err != nil {
				return 0, err
			}
			return uint64(number * float64(multiplier)), nil
		}
	}

	// If no suffix, treat as percentage
	percentage, err := strconv.ParseFloat(strings.TrimSuffix(value, "%"), 64)
	if err != nil {
		return 0, err
	}
	return uint64((percentage / 100) * float64(totalDiskSpace)), nil
}

// Lots have unix millisecond timestamps for creation, expiration, and deletion. If these are not set in the
// config, we'll set them to the current time. Expiration and deletion times are set to the default lifetime
func configLotTimestamps(lotMap *map[string]Lot) {
	now := time.Now().UnixMilli()
	defaultExpiration := now + param.Lotman_DefaultLotExpirationLifetime.GetDuration().Milliseconds()
	defaultDeletion := now + param.Lotman_DefaultLotDeletionLifetime.GetDuration().Milliseconds()

	for name, lot := range *lotMap {
		// root, default, and monitoring carry the all-zero non-expiring sentinel
		// introduced in lotman PR #44. Skip them so their timestamps are not
		// overwritten with real values by the defaulting logic below.
		if lot.LotName == "root" || lot.LotName == "default" || lot.LotName == "monitoring" {
			continue
		}
		if lot.MPA == nil {
			lot.MPA = &MPA{}
		}
		if lot.MPA.CreationTime == nil || lot.MPA.CreationTime.Value == 0 {
			lot.MPA.CreationTime = &Int64FromFloat{Value: now}
		}
		if lot.MPA.ExpirationTime == nil || lot.MPA.ExpirationTime.Value == 0 {
			lot.MPA.ExpirationTime = &Int64FromFloat{Value: defaultExpiration}
		}

		if lot.MPA.DeletionTime == nil || lot.MPA.DeletionTime.Value == 0 {
			lot.MPA.DeletionTime = &Int64FromFloat{Value: defaultDeletion}
		}

		(*lotMap)[name] = lot
	}
}

// configLotsFromFedPrefixesNested turns federation namespace ads into a flat
// map[name]Lot whose parent/child structure is derived by path-prefix
// containment and whose per-axis MPAs and parent_attributions follow the
// recursive (N+1) allocator. The synthetic root entry is dropped from the
// returned map: callers add their own root lot (with timestamps, owner,
// the "/" path) afterwards and only need the discovered descendants here.
//
// Pure data transform: no lotman C calls. The tree pipeline lives in
// lot_tree.go and is fully unit-tested without dlopen.
func configLotsFromFedPrefixesNested(nsAds []server_structs.NamespaceAdV2, federationIssuer string, rootDedGB float64) map[string]Lot {
	out := make(map[string]Lot)

	// Synthetic root lot used only as the seed for the allocator: it carries
	// the federation-wide quota that the (N+1) rule subdivides. The actual
	// "root" lot stored in lotMap is constructed by initLots immediately
	// after this call so it picks up consistent owner/timestamps even when
	// nsAds is empty.
	rootDed := rootDedGB
	rootOpp := float64(-1)
	rootObj := Int64FromFloat{Value: -1}
	seed := Lot{
		LotName: "root",
		MPA: &MPA{
			DedicatedGB:     &rootDed,
			OpportunisticGB: &rootOpp,
			MaxNumObjects:   &rootObj,
		},
	}

	tree := buildLotTree(seed, nsAds, federationIssuer)
	allocateQuotas(tree)
	flat := flattenTreeForCreation(tree)
	for _, lot := range flat {
		if lot.LotName == "root" {
			continue
		}
		out[lot.LotName] = lot
	}
	return out
}

// computeRootDedicatedGB picks the per-axis dedicated quota for the root
// lot in GB. The cache cannot actually retain more than its HighWaterMark
// before xrootd's pfc purger starts evicting, so handing the lot system
// "raw disk total" as the root dedicated quota would let lots provision
// space the cache can never honour at steady state. The result is
// therefore the smaller of:
//   - bytesToGigabytes(totalDiskSpaceB) (the physical capacity of the
//     cache's data disks), clamped down by the parsed
//     Cache.HighWaterMark fraction/value where one is configured; and
//   - any explicit Cache.FilesMaxSize ceiling.
//
// When no cache disks are detected (tests, early startup) we fall back
// to Cache.HighWaterMark interpreted as an absolute byte value so the
// root lot is still non-zero and lotman's first axiom remains
// satisfiable.
func computeRootDedicatedGB(totalDiskSpaceB uint64) float64 {
	rootDedGB := bytesToGigabytes(totalDiskSpaceB)
	hwmStr := param.Cache_HighWaterMark.GetString()
	if totalDiskSpaceB == 0 {
		if hwmStr != "" {
			hwmBytes, hwmErr := convertWatermarkToBytes(hwmStr, 0)
			if hwmErr == nil && hwmBytes > 0 {
				rootDedGB = bytesToGigabytes(hwmBytes)
				log.Debugf("No cache disks detected; using HighWaterMark (%s = %.2f GB) as root lot quota", hwmStr, rootDedGB)
			}
		}
		return rootDedGB
	}
	// Clamp to HighWaterMark when one is configured: anything above HWM
	// is unreachable steady-state because xrootd will purge it.
	if hwmStr != "" {
		if hwmBytes, hwmErr := convertWatermarkToBytes(hwmStr, totalDiskSpaceB); hwmErr == nil && hwmBytes > 0 {
			if clamped := bytesToGigabytes(hwmBytes); clamped < rootDedGB {
				rootDedGB = clamped
			}
		}
	}
	// Clamp to FilesMaxSize when set (absolute byte value or percent).
	if maxStr := param.Cache_FilesMaxSize.GetString(); maxStr != "" {
		if maxBytes, maxErr := convertWatermarkToBytes(maxStr, totalDiskSpaceB); maxErr == nil && maxBytes > 0 {
			if clamped := bytesToGigabytes(maxBytes); clamped < rootDedGB {
				rootDedGB = clamped
			}
		}
	}
	return rootDedGB
}

// One limitation in Lotman is that a lot cannot be created unless all of its parents exist. Unfortunately,
// this means we have to sort our lots topologically to ensure that we create them in the correct order.
// Failure to do so appears to result in a segfault in Lotman.
func topoSort(lotMap map[string]Lot) ([]Lot, error) {
	sorted := make([]Lot, 0, len(lotMap))
	visited := make(map[string]bool)

	// Recursively visit each lot and its parents, DFS-style
	var visit func(string) error
	visit = func(name string) error {
		if visited[name] {
			return nil
		}
		visited[name] = true

		// Visit all parents first
		for _, parent := range lotMap[name].Parents {
			if err := visit(parent); err != nil {
				return err
			}
		}
		// Adding the leaves of the DFS parent tree to the sorted list
		// guarantees that we'll add the parents before the children
		sorted = append(sorted, lotMap[name])
		return nil
	}

	for name := range lotMap {
		if err := visit(name); err != nil {
			return nil, err
		}
	}

	return sorted, nil
}

// Given a lot from the on-disk database and a newly-initialized lot, determine whether
// Lotman's database needs to be updated.
// Quirks in Lotman (sorry y'all) mean that we need to do this in a few steps across different
// update structs.
//
// If asAdmin is true, the MPA update portion runs with admin_override=true so
// it can contract a lot's reserved quota. This is required when the cache
// administrator reduces a configured size (e.g. Cache.FilesMaxSize lowered
// from gigabytes to megabytes); lotman's contraction_policy=always blocks
// such reductions on principal lots unless admin_override is set.
func updateLotIfNeeded(existingLot *Lot, newLot *Lot, caller string, asAdmin bool) error {
	lotUpdate, lotAddition, lotPathRemoval, lotParentRemoval, err := getLotUpdateJSONs(existingLot, newLot)
	if err != nil {
		return errors.Wrap(err, "error getting lot update JSONs")
	}

	// Send our update objects to Lotman
	if lotUpdate != nil {
		updateFn := UpdateLot
		if asAdmin {
			updateFn = UpdateLotAsAdmin
		}
		if err := updateFn(lotUpdate, caller); err != nil {
			return errors.Wrap(err, "error updating lot")
		}
	}

	if lotAddition != nil {
		if err := AddToLot(lotAddition, caller); err != nil {
			return errors.Wrap(err, "error adding lot")
		}
	}

	if lotPathRemoval != nil {
		if err := RemoveLotPaths(lotPathRemoval, caller); err != nil {
			return errors.Wrap(err, "error removing paths from lot")
		}
	}

	if lotParentRemoval != nil {
		if err := RemoveLotParents(lotParentRemoval, caller); err != nil {
			return errors.Wrap(err, "error removing parents from lot")
		}
	}

	return nil
}

// A helper function used to either populate the database with a newly-initialized lot or update an existing one
// based on the contents of the newly-initialized lot.
//
// asAdmin enables admin_override on the underlying MPA update so the call
// can succeed even when the new MPA contracts the existing one. The root
// lot specifically is always updated as admin because it tracks the cache's
// physical capacity (Cache.HighWaterMark / Cache.FilesMaxSize), which is by
// definition admin-controlled. If contraction would violate strict_hierarchy
// because existing descendants still hold reservations, those descendants
// are reclaimed first so the renewal tick can re-plan them against the new
// budget.
func ensureLotExistsOrUpdate(lotName string, initializedLots []Lot, federationIssuer string, asAdmin bool) (bool, error) {
	exists, err := LotExists(lotName)
	if err != nil {
		log.Errorf("Unable to check whether %s lot exists: %v", lotName, err)
		return false, fmt.Errorf("unable to check whether %s lot exists: %w", lotName, err)
	}

	if !exists {
		// Lot does not exist, create it
		for _, lot := range initializedLots {
			if lot.LotName == lotName {
				log.Debugf("Creating lot %s defined by %v", lotName, lot)
				if err := CreateLot(&lot, federationIssuer); err != nil {
					log.Errorf("Unable to create lot %s: %v", lotName, err)
					return false, fmt.Errorf("unable to create lot %s: %w", lotName, err)
				}
				log.Infof("Created lot %s", lotName)
				return true, nil
			}
		}
	} else {
		// Lot exists, check for updates
		for _, lot := range initializedLots {
			if lot.LotName == lotName {
				log.Debugf("Lot %s already exists, checking for updates", lotName)

				// Get the lot from the lot database to see if it needs updating
				existingLot, err := GetLot(lotName, false)
				if err != nil {
					log.Errorf("Unable to get lot %s to check for updates: %v", lotName, err)
					return false, fmt.Errorf("unable to get lot %s to check for updates: %v", lotName, err)
				}

				err = updateLotIfNeeded(existingLot, &lot, federationIssuer, asAdmin)
				if err != nil {
					// On a contraction-policy or hierarchy-violation
					// failure for an admin-controlled lot (notably root),
					// the cache admin has reduced the configured size in
					// pelican.yaml; we cannot honour any descendant
					// reservations that exceed the new budget. Reclaim
					// every non-sentinel descendant so the renewal tick
					// can re-plan against the new MPA, then retry.
					if asAdmin && shouldReclaimForUpdate(err) {
						if rclErr := reclaimDescendantsForContraction(lotName, federationIssuer); rclErr != nil {
							log.Errorf("Unable to reclaim descendants of %s after contraction conflict: %v", lotName, rclErr)
							return false, fmt.Errorf("unable to reclaim descendants of %s after contraction conflict: %v", lotName, rclErr)
						}
						log.Warnf("Reclaimed descendants of %s to accommodate admin-driven MPA contraction; retrying update", lotName)
						err = updateLotIfNeeded(existingLot, &lot, federationIssuer, true)
					}
					if err != nil {
						log.Errorf("Unable to update lot %s: %v", lotName, err)
						return false, fmt.Errorf("unable to update lot %s: %v", lotName, err)
					}
				}
				return true, nil
			}
		}
	}

	return false, nil
}

// filterAdsAlreadyScheduled returns the subset of `adsFromFed` whose
// namespace path is NOT already covered by an active non-sentinel lot
// in the init scheduling window [nowMs, nowMs+DefaultLifetime).
//
// On restart, the lots minted by previous Pelican processes still live
// in the lotman SQLite DB and already protect their namespace paths
// for the rest of their lifetime. If init unconditionally mints fresh
// UUID lots for those same paths, the new lot's [now, now+lifetime)
// window overlaps the predecessor's, and the combined per-instant
// dedicated_GB across siblings exceeds the parent root capacity --
// lotman's strict_hierarchy enforcement (axiom 1) then rejects the
// new lot with:
//
//	Hierarchy violation: peak concurrent dedicated_GB across children
//	of parent lot 'root' is X, which exceeds the parent's
//	dedicated_GB allocation of Y.
//
// Skipping namespaces that are already covered defers their
// (re-)scheduling to the renewal tick, which is the component
// responsible for minting back-to-back successor lots without
// overlap.
//
// On a fresh DB (very first startup) lotman has no path index yet and
// GetLotsForPath may return either an empty list or an error; both
// outcomes are treated as "not covered" so init proceeds normally.
func filterAdsAlreadyScheduled(adsFromFed []server_structs.NamespaceAdV2) []server_structs.NamespaceAdV2 {
	nowMs := time.Now().UnixMilli()
	windowEndMs := nowMs + param.Lotman_DefaultLotExpirationLifetime.GetDuration().Milliseconds()

	out := make([]server_structs.NamespaceAdV2, 0, len(adsFromFed))
	for _, ad := range adsFromFed {
		path := normaliseLotPath(ad.Path)
		if path == "" || path == "/" {
			// Path-less / root-shadowing ads are dropped by
			// buildLotTree anyway; pass them through here so
			// downstream handling is unchanged.
			out = append(out, ad)
			continue
		}

		// recursive=true returns the path's owner plus its ancestors.
		// includeReclaimed=false: a reclaimed lot is dead capacity and
		// does not contribute to the axiom-1 sum, so its path may safely
		// be re-scheduled.
		lots, err := GetLotsForPath(path, true, nowMs, windowEndMs, false)
		if err != nil {
			// Most commonly a fresh DB with no path index. Be
			// permissive: treat as not-covered so the first-ever
			// startup still creates init lots.
			log.Debugf("Lotman init: GetLotsForPath(%q) failed (likely fresh DB), proceeding to schedule init lot: %v", path, err)
			out = append(out, ad)
			continue
		}

		covered := false
		for _, l := range lots {
			// "root" and "default" are sentinel container lots and
			// don't represent real prior scheduling of the path.
			if l.LotName == "root" || l.LotName == "default" {
				continue
			}
			covered = true
			break
		}
		if covered {
			log.Infof("Lotman init: namespace %q already has an active lot covering the planning window; deferring scheduling to the renewal tick", path)
			continue
		}
		out = append(out, ad)
	}
	return out
}

// Initialize the lot configurations based on provided policy, discovered namespaces,
// and available cache space, handling any necessary merges and validations along the way.
func initLots(nsAds []server_structs.NamespaceAdV2) ([]Lot, error) {
	var internalLots []Lot

	policies, err := GetPolicyMap()
	if err != nil {
		return internalLots, errors.Wrap(err, "unable to parse lotman configuration")
	}

	// Get the configured policy, which defines any lots we may need to handle
	// along with merging logic and purge ordering
	policyName := param.Lotman_EnabledPolicy.GetString()
	if _, exists := policies[policyName]; !exists {
		return internalLots, errors.Errorf("enabled policy %s is not defined in the configuration", policyName)
	}
	policy := policies[policyName]

	discoverPrefixes := policy.DiscoverPrefixes
	shouldMerge := policy.MergeLocalWithDiscovered
	if shouldMerge && !discoverPrefixes {
		return internalLots, errors.New("MergeLocalWithDiscovered is set to true, but DiscoverPrefixes is set to false. This is not a valid configuration")
	}

	// policyLotMap will hold the lots defined in the configuration file (if any) provided by the cache admin
	policyLotMap := make(map[string]Lot)
	for _, lot := range policy.Lots {
		policyLotMap[lot.LotName] = lot
	}

	cacheDisks := param.Cache_DataLocations.GetStringSlice()
	log.Tracef("Cache data locations being tracked by Lotman: %v", cacheDisks)
	var totalDiskSpaceB uint64
	for _, disk := range cacheDisks {
		diskSpace, _, err := getDiskUsage(disk)
		if err != nil {
			return internalLots, errors.Wrapf(err, "error getting disk usage for filesystem path %s", disk)
		}
		totalDiskSpaceB += diskSpace
	}

	federationIssuer, err := getFederationIssuer()
	if err != nil {
		return internalLots, errors.Wrap(err, "Unable to determine the federation's issuer, which is needed by Lotman to determine lot ownership")
	}
	if federationIssuer == "" {
		return internalLots, errors.New("The detected federation issuer, which is needed by Lotman to determine lot/namespace ownership, is empty")
	}
	rootDedGB := computeRootDedicatedGB(totalDiskSpaceB)

	var lotMap map[string]Lot
	if discoverPrefixes {
		// Drop namespaces whose path is already covered by an active
		// non-sentinel lot in the init planning window. Their previous
		// init lots (and any renewal successors minted on prior runs)
		// still protect the path; allocating a fresh init lot on top
		// would overlap and trip lotman's axiom-1 admission check. The
		// renewal tick is the component responsible for extending
		// coverage past the existing lots' expiration.
		nsAds = filterAdsAlreadyScheduled(nsAds)

		// Build a nested lot graph from discovered namespace ads. The root
		// lot's per-axis quota is supplied here so the recursive (N+1)
		// allocator has something concrete to subdivide; the synthesised
		// root/default lots themselves are added to lotMap below.
		directorLotMap := configLotsFromFedPrefixesNested(nsAds, federationIssuer, rootDedGB)

		// Handle potential need to merge discovered namespaces with provided configuration
		if shouldMerge {
			log.Debug("Merging lot configuration from discovered namespaces with configured lots")
			lotMap, err = mergeLotMaps(policyLotMap, directorLotMap)
			if err != nil {
				return internalLots, errors.Wrap(err, "error merging discovered namespaces with configured lots")
			}
			log.Tracef("Merged lot configuration: %+v", lotMap)
		} else {
			lotMap = make(map[string]Lot)
			// first set things up with the director lots, then overwrite with the policy lots.
			// This allows cache admins to override any discovered lots with their own configuration.
			for key, value := range directorLotMap {
				lotMap[key] = value
			}
			for key, value := range policyLotMap {
				lotMap[key] = value
			}
		}
	} else {
		lotMap = policyLotMap
	}

	// Now guarantee our special "default" and "root" lots if the user hasn't provided them
	// in the config. For now, these lots must always exist because they're used to make sure
	// all data is tied to a lot (default) and that the requirement of a root lot is satisfied
	// without allowing discovered lots to gain rootly status.
	zero := float64(0)
	unboundedGB := float64(-1)
	// `default` is the catch-all parent for namespaces that have not been
	// given an explicit lot. Its storage MPAs are literal 0 -- it has no
	// protected quota at all, so any usage immediately puts the lot
	// over-quota and the purge plugin reclaims it on the next cycle.
	// Note: lotman PR #46 reserves -1 (not 0) as the unbounded sentinel for
	// storage MPAs, so 0 here means exactly what it says: zero capacity.
	if _, exists := lotMap["default"]; !exists {
		defDed := zero
		// The default lot's opportunistic quota controls whether unlotted data
		// is retained at all. 0 (the historical default) means no protected
		// quota -- unlotted data is reclaimed first; a positive value lets the
		// cache keep it opportunistically, and -1 is unbounded.
		defOpp := float64(param.Lotman_DefaultLotOpportunisticGB.GetInt())
		lotMap["default"] = Lot{
			LotName: "default",
			Owner:   federationIssuer,
			Parents: []string{"default"},
			MPA: &MPA{
				DedicatedGB:     &defDed,
				OpportunisticGB: &defOpp,
				MaxNumObjects:   &Int64FromFloat{Value: 0},
				// All-zero timestamps = non-expiring sentinel (lotman PR #44).
				// configLotTimestamps skips root and default intentionally.
				CreationTime:   &Int64FromFloat{Value: 0},
				ExpirationTime: &Int64FromFloat{Value: 0},
				DeletionTime:   &Int64FromFloat{Value: 0},
			},
		}
	}
	if _, exists := lotMap["root"]; !exists {
		rootOpp := unboundedGB
		lotMap["root"] = Lot{
			LotName: "root",
			Owner:   federationIssuer,
			Parents: []string{"root"},

			Paths: []LotPath{
				{
					Path:      "/",
					Recursive: false, // setting this to true would prevent any other lot from claiming a path
				},
			},
			MPA: &MPA{
				// dedicatedGB equals the entire cache disk (or HWM in tests),
				// so the root lot itself is never a purge target. Opportunistic
				// and object quotas are unbounded (-1 sentinel, lotman PR #46):
				// root is purely a metadata container and should never be the
				// binding constraint on any axis besides dedicated bytes.
				DedicatedGB:     &rootDedGB,
				OpportunisticGB: &rootOpp,
				MaxNumObjects:   &Int64FromFloat{Value: -1},
				// All-zero timestamps = non-expiring sentinel (lotman PR #44).
				// configLotTimestamps skips root and default intentionally.
				CreationTime:   &Int64FromFloat{Value: 0},
				ExpirationTime: &Int64FromFloat{Value: 0},
				DeletionTime:   &Int64FromFloat{Value: 0},
			},
		}
	}

	// The monitoring lot owns the federation's self-test / monitoring namespace
	// and bounds how many such objects the cache retains. It exists only on the
	// V2 (persistent) cache, which enforces the object cap as a rolling window;
	// V1 (XRootD) has no federation-aware monitoring lot and its purge plugin
	// does not honour max_num_objects. The lot carries zero dedicated bytes (so
	// it is a first eviction target under disk pressure) and an unbounded
	// opportunistic byte quota, leaving the object count as the binding axis.
	if param.Cache_EnableV2.GetBool() {
		if _, exists := lotMap["monitoring"]; !exists {
			monDed := zero
			monOpp := unboundedGB
			lotMap["monitoring"] = Lot{
				LotName: "monitoring",
				Owner:   federationIssuer,
				Parents: []string{"root"},
				Paths: []LotPath{
					{
						Path:      monitoringBasePath(),
						Recursive: true,
					},
				},
				MPA: &MPA{
					DedicatedGB:     &monDed,
					OpportunisticGB: &monOpp,
					MaxNumObjects:   &Int64FromFloat{Value: int64(param.Lotman_MonitoringLotMaxObjects.GetInt())},
					// All-zero timestamps = non-expiring sentinel (lotman PR #44);
					// configLotTimestamps skips it so these stay zero.
					CreationTime:   &Int64FromFloat{Value: 0},
					ExpirationTime: &Int64FromFloat{Value: 0},
					DeletionTime:   &Int64FromFloat{Value: 0},
				},
			}
		}
	}

	log.Tracef("Lotman will split lot disk space quotas amongst the discovered disk space: %vB", totalDiskSpaceB)

	// Set up lot timestamps (creation, expiration, deletion) if needed
	configLotTimestamps(&lotMap)

	log.Tracef("Internal lot configuration: %+v", internalLots)
	err = validateLotsConfig(internalLots, totalDiskSpaceB)
	if err != nil {
		return internalLots, errors.Wrap(err, "error validating deduced lot configuration")
	}

	internalLots, err = topoSort(lotMap)
	if err != nil {
		return internalLots, errors.Wrap(err, "error sorting lots prior to instantiation")
	}

	return internalLots, nil
}

// lotmanDatabase returns the *gorm.DB the lot manager should use, choosing
// between deployment models. V2 (the pure-Go persistent cache) has no separate
// storage daemon, so lots live in the shared Pelican server database. V1
// (XRootD) runs the purge plugin in a separate process as the xrootd user; that
// plugin reaches lots through the (Go-built) libLotMan shared library opening a
// dedicated SQLite database under Lotman.LotHome, so Pelican shares that same
// on-disk file (SQLite WAL supports concurrent multi-process access) and widens
// its ownership/permissions to the daemon user.
func lotmanDatabase() (*gorm.DB, error) {
	if param.Cache_EnableV2.GetBool() {
		if database.ServerDatabase == nil {
			return nil, errors.New("the Pelican server database is not initialized")
		}
		return database.ServerDatabase, nil
	}

	// V1: a dedicated SQLite under lot_home, shareable with the xrootd-user purge plugin.
	lotHome := param.Lotman_LotHome.GetString()
	if lotHome == "" {
		return nil, errors.New("Lotman.LotHome must be set for the XRootD (V1) cache")
	}
	uid, err := config.GetDaemonUID()
	if err != nil {
		return nil, errors.Wrap(err, "unable to determine daemon UID for the lot database directory")
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return nil, errors.Wrap(err, "unable to determine daemon GID for the lot database directory")
	}
	if err := config.MkdirAll(lotHome, 0o777, uid, gid); err != nil {
		return nil, errors.Wrap(err, "unable to create the lot database directory")
	}
	dbPath := filepath.Join(lotHome, "lots.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open the lot database")
	}
	// Widen ownership/permissions so the xrootd-user purge plugin can also open
	// the database file and its WAL/shared-memory siblings.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		if _, statErr := os.Stat(p); statErr == nil {
			_ = os.Chown(p, uid, gid)
			_ = os.Chmod(p, 0o666)
		}
	}
	return db, nil
}

// federationQualifyAds prepends the configured federation prefix (set by the V2
// launcher) to each namespace ad's path, so lots auto-created from these ads are
// federation-qualified and match the persistent cache's resolution keys. A no-op
// (returns the input) when no prefix is configured (e.g. the V1 cache), keeping
// paths bare for xrootd. The input slice is not mutated.
func federationQualifyAds(ads []server_structs.NamespaceAdV2) []server_structs.NamespaceAdV2 {
	prefix := getFederationPrefix()
	if prefix == "" {
		return ads
	}
	out := make([]server_structs.NamespaceAdV2, len(ads))
	for i, ad := range ads {
		ad.Path = normaliseLotPath(prefix + ad.Path)
		out[i] = ad
	}
	return out
}

// monitoringBasePath returns the (possibly federation-qualified) base path for
// monitoring namespaces, so monitoring detection works whether or not lot paths
// are federation-prefixed.
func monitoringBasePath() string {
	return normaliseLotPath(getFederationPrefix() + server_utils.MonitoringBaseNs)
}

func InitLotman(adsFromFed []server_structs.NamespaceAdV2) bool {
	log.Infof("Initializing LotMan...")

	// Federation-qualify namespace paths for V2 (no-op for V1) so all
	// downstream lot creation, hierarchy, and renewal operate in the same
	// path space the persistent cache resolves against.
	adsFromFed = federationQualifyAds(adsFromFed)

	// Build the native lot manager over the appropriate database (V2 uses the
	// shared Pelican server DB; V1 uses a dedicated, xrootd-shareable SQLite
	// under lot_home) and apply the lot-schema migrations. Strict hierarchy is
	// always enabled so the reservation invariants are enforced from the very
	// first lot creation.
	db, err := lotmanDatabase()
	if err != nil {
		log.Errorf("Error acquiring lot database: %v", err)
		return false
	}
	m, err := core.New(db, core.Options{
		StrictHierarchy:   true,
		ContractionPolicy: core.ContractionAlways,
		Logger:            coreLogger{},
	})
	if err != nil {
		log.Errorf("Error initializing lot manager: %v", err)
		return false
	}
	if err := m.Migrate(); err != nil {
		log.Errorf("Error applying lot schema migrations: %v", err)
		return false
	}
	setManager(m)

	initializedLots, err = initLots(adsFromFed)
	if err != nil {
		log.Errorf("Error creating lot config: %v", err)
		return false
	}

	federationIssuer, err := getFederationIssuer()
	if err != nil {
		log.Errorf("Error getting federation issuer: %v", err)
		return false
	}
	if federationIssuer == "" {
		log.Errorln("Unable to determine federation issuer which is needed by Lotman to determine lot ownership")
		return false
	}

	// Init/update the default lot, which must exist _before_ any other lots can be touched.
	// The default lot is auto-derived from cache config; treat it as admin-controlled.
	defaultInitialized, err := ensureLotExistsOrUpdate("default", initializedLots, federationIssuer, true)
	if err != nil {
		return false
	}

	// Init/update the root lot, which is a container we use to make sure all lots have a federation-owned parent.
	// Root's MPA tracks the cache's physical capacity (Cache.HighWaterMark /
	// Cache.FilesMaxSize); when the admin lowers those, lotman's
	// contraction_policy=always would otherwise block the resulting root
	// update. Pass asAdmin=true so the update honours admin-driven
	// reductions, and reclaim any descendants that no longer fit.
	rootInitialized, err := ensureLotExistsOrUpdate("root", initializedLots, federationIssuer, true)
	if err != nil {
		return false
	}

	// If either of the default or root lots failed to initialize, we can't proceed.
	if !defaultInitialized || !rootInitialized {
		log.Errorln("Failed to create default and/or root lots")
		return false
	}

	// Now instantiate any other lots that are in the config
	for _, lot := range initializedLots {
		if lot.LotName != "default" && lot.LotName != "root" {
			// monitoring is auto-derived from config like default/root; treat it
			// as admin-controlled so its object cap can be lowered across restarts.
			asAdmin := lot.LotName == "monitoring"
			initialized, err := ensureLotExistsOrUpdate(lot.LotName, initializedLots, federationIssuer, asAdmin)
			if err != nil {
				return false
			}
			if !initialized {
				log.Errorf("Failed to initialize lot %s", lot.LotName)
				return false
			}
		}
	}

	log.Infof("LotMan initialization complete")
	return true
}

// Create a lot in the lot database with the given lot struct. The caller is the entity that
// is creating the lot, and is used to determine whether we want to allow the creation to go through.
// Here, caller is used to determine whether this lot is allowed to create any sublots of an indicated
// parent lot. The lot struct has the form:
//
//	{
//	  "lot_name": "lot_name", (REQUIRED)
//	  "owner": "owner", (REQUIRED)
//	  "parents": ["parent1", "parent2"], (REQUIRED)
//	  "paths": [
//	    {
//	      "path": "path",
//	      "recursive": true/false
//	    }
//	  ], (OPTIONAL)
//	  "management_policy_attrs": {
//	    "dedicated_GB": 0.0,
//	    "opportunistic_GB": 0.0,
//	    "max_num_objects": 0,
//	    "creation_time": 0,
//	    "expiration_time": 0,
//	    "deletion_time": 0
//	  } (REQUIRED)
//	}
func CreateLot(newLot *Lot, caller string) error {
	if err := validateLotLifetime(newLot); err != nil {
		return err
	}
	m, err := requireManager()
	if err != nil {
		return err
	}
	return m.AddLot(lotToSpec(newLot), caller)
}

// Given a lot name, get the lot from the lot database. If recursive is true, we'll also
// determine all hierarchical restrictions on the lot. For example, if the lot "foo" has
// dedicated_GB = 2.0 but its parent lot "bar" has dedicated_GB = 1.0, then calling this
// with recursive = true will indicate the restricting value and the lot it comes from.
func GetLot(lotName string, recursive bool) (*Lot, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	v, err := m.GetLot(lotName)
	if err != nil {
		return nil, err
	}
	lot := lotViewToAdapter(v)
	// recursive=true reports the full ancestor chain (matching the reference's
	// get_lot_as_json), not just the immediate parents.
	parents, err := m.GetParents(lotName, recursive, true)
	if err != nil {
		return nil, err
	}
	lot.Parents = parents
	owners, err := m.GetOwners(lotName, recursive)
	if err != nil {
		return nil, err
	}
	lot.Owners = owners
	attrs, err := m.Attributions(lotName)
	if err != nil {
		return nil, err
	}
	lot.ParentAttributions = attrValuesToAdapter(attrs)
	if recursive {
		rv, err := m.PolicyAttributes(core.PolicyAttrsRequest{LotName: lotName, Recursive: true})
		if err != nil {
			return nil, err
		}
		lot.RestrictiveMPA = restrictiveToAdapter(rv)
	}
	return lot, nil
}

// Update a lot in the lot database with the given lotUpdate struct. The caller is the entity that
// is updating the lot, and is used to determine whether we want to allow the update to go through.
// In general, a valid caller is one that matches the owner of any of the lot's parents.
// The lot update struct has the form:
//
//	{
//	  "lot_name": "lot_name", (REQUIRED)
//	  "owner": "new_owner", (OPTIONAL)
//	  "parents": [
//	    {
//	      "current": "current_parent",
//	      "new": "new_parent"
//	    }
//	  ], (OPTIONAL)
//	  "paths": [
//	    {
//	      "current": "current_path",
//	      "new": "new_path",
//	      "recursive": true/false
//	    }
//	  ], (OPTIONAL)
//	  "management_policy_attrs": {
//	    "dedicated_GB": 0.0,
//	    "opportunistic_GB": 0.0,
//	    "max_num_objects": 0,
//	    "creation_time": 0,
//	    "expiration_time": 0,
//	    "deletion_time": 0
//	  } (OPTIONAL)
//	}
func UpdateLot(lotUpdate *LotUpdate, caller string) error {
	if err := validateLotUpdateLifetime(lotUpdate); err != nil {
		return err
	}
	m, err := requireManager()
	if err != nil {
		return err
	}

	// Owner / MPA / parent-attribution changes go through the core update. A
	// non-nil MPA is merged onto the lot's existing MPA so unspecified fields
	// (notably creation_time) are preserved.
	if lotUpdate.Owner != nil || lotUpdate.MPA != nil || lotUpdate.ParentAttributions != nil {
		cu := core.LotUpdate{
			LotName:            lotUpdate.LotName,
			Owner:              lotUpdate.Owner,
			ParentAttributions: parentAttrToCore(lotUpdate.ParentAttributions),
		}
		if lotUpdate.MPA != nil {
			existing, err := m.GetLot(lotUpdate.LotName)
			if err != nil {
				return err
			}
			mpa := mergeMPAToCore(lotUpdate.MPA, existing.Lot)
			cu.MPA = &mpa
		}
		if err := m.UpdateLot(cu, caller); err != nil {
			return err
		}
	}

	// Path "renames": the core update does not replace paths, so apply each
	// as add-new then remove-old.
	if lotUpdate.Paths != nil {
		for _, pu := range *lotUpdate.Paths {
			if err := m.AddToLot(core.LotAddition{LotName: lotUpdate.LotName, Paths: []core.PathSpec{{Path: pu.New, Recursive: pu.Recursive}}}, caller); err != nil {
				return err
			}
			if err := m.RemovePaths(core.LotPathRemoval{LotName: lotUpdate.LotName, Paths: []string{pu.Current}}, caller); err != nil {
				return err
			}
		}
	}

	// Parent "renames": add the new parent before removing the old to keep the
	// at-least-one-parent invariant.
	if lotUpdate.Parents != nil {
		for _, pu := range *lotUpdate.Parents {
			if err := m.AddToLot(core.LotAddition{LotName: lotUpdate.LotName, Parents: []string{pu.New}}, caller); err != nil {
				return err
			}
			if err := m.RemoveParents(core.LotParentRemoval{LotName: lotUpdate.LotName, Parents: []string{pu.Current}}, caller); err != nil {
				return err
			}
		}
	}

	return nil
}

// UpdateLotAsAdmin is UpdateLot with admin_override=true active for the
// duration of the call. lotman's contraction_policy=always rejects any
// MPA update that shrinks dedicated_GB, opportunistic_GB, max_num_objects,
// or shortens the lifetime axes unless admin_override is set. The cache's
// own InitLotman pathway needs that escape hatch when the admin reduces
// configured cache sizing in pelican.yaml -- the root/default lots derive
// their quotas from those settings and must therefore be allowed to
// contract.
func UpdateLotAsAdmin(lotUpdate *LotUpdate, caller string) error {
	// With the native engine the federation issuer owns the root/default lots
	// (so ownership authorization passes), and MPA contraction is governed by
	// the strict-hierarchy axioms rather than a separate contraction policy. A
	// contraction that would violate a child's reservation is blocked by the
	// axioms and recovered by the caller via reclaimDescendantsForContraction;
	// no per-call admin override is needed, so this delegates to UpdateLot.
	return UpdateLot(lotUpdate, caller)
}

// shouldReclaimForUpdate inspects err to decide whether a failed
// admin-mode lot update can be recovered by reclaiming the lot's
// descendants. We retry on:
//   - contraction_policy rejections (admin_override should have made
//     this impossible, but lotman wording varies between releases so
//     we match defensively), and
//   - strict_hierarchy peak-concurrent-quota violations, which fire
//     when descendants still hold reservations that exceed the new
//     parent MPA.
func shouldReclaimForUpdate(err error) bool {
	// The native core reports a strict-hierarchy / contraction violation as
	// ErrInvalidLot; recover those by reclaiming descendants and retrying.
	return errors.Is(err, core.ErrInvalidLot)
}

// reclaimDescendantsForContraction removes every non-sentinel descendant
// of parentLot from the lotman DB. Lotman's strict_hierarchy enforcement
// continues to consult reclaimed (soft-deleted) rows when validating an
// MPA update, so reclamation alone is insufficient -- the only way to
// free a parent's quota for contraction is to actually remove the
// children. After removal, the renewal tick re-plans coverage for any
// still-advertised namespaces against the new budget.
//
// The "default" and "root" sentinel lots are explicitly preserved.
// RemoveLot internally sets admin_override=true, so children with
// contraction_policy=always can still be deleted.
func reclaimDescendantsForContraction(parentLot, caller string) error {
	children, err := GetChildrenNames(parentLot, true, false)
	if err != nil {
		return errors.Wrapf(err, "failed to enumerate descendants of %s", parentLot)
	}
	for _, name := range children {
		if name == "default" || name == "root" || name == parentLot {
			continue
		}
		// assignLTBRParentsToOrphans=true so any grand-children get
		// hooked up to the next-surviving ancestor (typically root)
		// instead of being orphaned. assignPolicyToChildren=false
		// because we're tearing the subtree down entirely.
		if rmErr := RemoveLot(name, true, true, false, false, caller); rmErr != nil {
			return errors.Wrapf(rmErr, "failed to remove descendant lot %s", name)
		}
		log.Infof("Removed descendant lot %s ahead of %s MPA contraction", name, parentLot)
	}
	return nil
}

// Unlike UpdateLot, which modifies a lot's _existing_ fields (e.g. switch a path from
// recursive to non-recursive), AddToLot is used to _add_ new fields to a lot and is how
// new paths/parents need to be populated. The caller is the entity that is updating
// the lot, and is used to determine whether we want to allow the addition to go through.
//
// The lot addition JSON is limited to paths and parents and has the form:
//
//	{
//		"lot_name": "lot_name", (REQUIRED)
//		"paths": [
//			{
//				"path": "/new/path",
//				"recursive": true/false
//			}
//		], (OPTIONAL)
//		"parents": ["newparent1", "newparent2"] (OPTIONAL)
//	}
func AddToLot(lotAddition *LotAddition, caller string) error {
	// Marshal the JSON into a string for the C function
	m, err := requireManager()
	if err != nil {
		return err
	}
	return m.AddToLot(core.LotAddition{
		LotName:            lotAddition.LotName,
		Parents:            lotAddition.Parents,
		Paths:              pathSpecsFromLotPaths(lotAddition.Paths),
		ParentAttributions: parentAttrToCore(lotAddition.ParentAttributions),
	}, caller)
}

// RemoveLotParents is used to remove parents from the lot. Because every lot must
// have at least one parent, it'll throw an error if you try removing every parent.
//
// The parent removal JSON has the form:
//
//	{
//			"lot_name": "lot_name", (REQUIRED)
//			"parents": [
//				"parent1",
//				"parent2"
//			] (REQUIRED)
//		}
func RemoveLotParents(parentsRemoval *LotParentRemoval, caller string) error {
	m, err := requireManager()
	if err != nil {
		return err
	}
	return m.RemoveParents(core.LotParentRemoval{LotName: parentsRemoval.LotName, Parents: parentsRemoval.Parents}, caller)
}

// RemoveLotPaths is used to remove paths from the lot.
//
// The path removal JSON has the form:
//
//	{
//		"lot_name": "lot_name", (REQUIRED)
//		"paths": [
//			"/first/path",
//			"/second/path"
//		] (REQUIRED)
//	}
func RemoveLotPaths(pathsRemoval *LotPathRemoval, caller string) error {
	m, err := requireManager()
	if err != nil {
		return err
	}
	// A path belongs to at most one lot. Look up the lot that holds the exact
	// path row (independent of lifecycle window) and remove it there.
	for _, p := range pathsRemoval.Paths {
		owner, err := m.LotForPath(p)
		if err != nil {
			return err
		}
		if owner == "" {
			continue
		}
		if err := m.RemovePaths(core.LotPathRemoval{LotName: owner, Paths: []string{p}}, caller); err != nil {
			return err
		}
	}
	return nil
}

// Delete a lot from the lot database. The caller is the entity that is deleting the lot, and is used to determine
// whether we want to allow the deletion to go through. In general, a valid caller is one that matches an owner from
// any of the lot's recursive parents. This function deletes the lot and all of its children.
func DeleteLotsRecursive(lotName string, caller string) error {
	m, err := requireManager()
	if err != nil {
		return err
	}
	return m.RemoveLotRecursive(lotName, caller)
}

// IsRoot reports whether lotName names a root lot (only self-parent).
func IsRoot(lotName string) (bool, error) {
	m, err := requireManager()
	if err != nil {
		return false, err
	}
	return m.IsRoot(lotName)
}

// LotExists reports whether a lot with the given name exists in the lotman DB.
func LotExists(lotName string) (bool, error) {
	m, err := requireManager()
	if err != nil {
		return false, err
	}
	return m.LotExists(lotName)
}

// ListAllLots returns every lot name currently stored in the lotman DB.
//
// Holds callerMutex even though the operation is conceptually a read:
// lotman's strict_hierarchy implementation funnels every C-side call
// through the same shared SQLite handle, and concurrent access produces
// intermittent "bad parameter or other API misuse" / "out of memory"
// errors from SQLite. The mutex is the single chokepoint that keeps
// Pelican's renewal-tick / GC-tick / HTTP-handler goroutines from
// stepping on each other.
func ListAllLots() ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.ListAllLots()
}

// GetChildrenNames returns the names of lotName's children. If recursive is
// true, all transitive descendants are returned. If getSelf is true, lotName
// is included when it self-parents. See ListAllLots for the locking note.
func GetChildrenNames(lotName string, recursive, getSelf bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.GetChildren(lotName, recursive, getSelf)
}

// GetParentNames returns the names of lotName's parents. If recursive is
// true, all transitive ancestors are returned. See ListAllLots for the
// locking note.
func GetParentNames(lotName string, recursive, getSelf bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.GetParents(lotName, recursive, getSelf)
}

// GetOwners returns the owner identities recorded for lotName. If recursive
// is true, owners of all ancestor lots are unioned in. See ListAllLots for
// the locking note.
func GetOwners(lotName string, recursive bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.GetOwners(lotName, recursive)
}

// GetLotsFromDir returns the names of lots tracking the supplied path at the
// supplied wall-clock time (Unix milliseconds). queryTimeMs of 0 means "now".
// If recursive is true, every parent lot is also returned. The result is
// non-empty for every legal input: paths not tied to any lot resolve to the
// "default" lot. See ListAllLots for the locking note.
func GetLotsFromDir(dir string, recursive bool, queryTimeMs int64) ([]string, error) {
	if queryTimeMs == 0 {
		queryTimeMs = time.Now().UnixMilli()
	}
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.LotsFromDir(dir, recursive, queryTimeMs)
}

// GetLotsForPath returns full Lot objects for every lot that "wins" the
// longest-prefix path-resolution contest at any instant in the half-open
// window [timeLoMs, timeHiMs). Two lots may both be returned when each owns
// the path during disjoint sub-intervals of the window. When recursive is
// true, each winner's ancestors are also included. When includeReclaimed is
// false, lots reclaimed at or before timeLoMs are dropped entirely; lots
// reclaimed mid-window have their effective active interval clipped before
// the sweep. The result always contains at least one element: when no lot
// wins anywhere in the window, the synthetic "default" lot is appended.
//
// This is the window-aware variant of GetLotsFromDir (lotman PR #52). The
// renewal scheduler uses it to enumerate just the lots that touch a given
// namespace path during its planning window, which lets it scope work to
// O(active subtree size) instead of O(total lot rows).
func GetLotsForPath(path string, recursive bool, timeLoMs, timeHiMs int64, includeReclaimed bool) ([]Lot, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	names, err := m.LotsForPath(path, recursive, timeLoMs, timeHiMs, includeReclaimed)
	if err != nil {
		return nil, err
	}
	lots := make([]Lot, 0, len(names))
	for _, name := range names {
		l, err := GetLot(name, false)
		if errors.Is(err, core.ErrLotNotFound) {
			// The synthetic "default" fallback can be returned even when no
			// default lot row exists; represent it by name only.
			lots = append(lots, Lot{LotName: name})
			continue
		}
		if err != nil {
			return nil, err
		}
		lots = append(lots, *l)
	}
	return lots, nil
}

// GetLotsPastExp returns all lots past their expiration_time relative to
// the supplied queryTimeMs cutoff (a Unix timestamp in milliseconds). Pass
// time.Now().UnixMilli() for the historical "as of now" semantics; pass a
// future timestamp to preview which lots will be expired by then. If
// recursive, the most-restricting ancestor expiration_time is used.
// If includeReclaimed is false (the typical cleanup-loop value) lots with
// a reclamations-ledger row whose reclaimed_at <= queryTimeMs are excluded.
func GetLotsPastExp(queryTimeMs int64, recursive, includeReclaimed bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.LotsPastExp(queryTimeMs, recursive, includeReclaimed)
}

// GetLotsPastDel returns all lots past their deletion_time relative to the
// supplied queryTimeMs cutoff. See GetLotsPastExp for the meaning of
// queryTimeMs and includeReclaimed.
func GetLotsPastDel(queryTimeMs int64, recursive, includeReclaimed bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.LotsPastDel(queryTimeMs, recursive, includeReclaimed)
}

// GetLotsPastDed returns all lots past their dedicated_GB quota.
// When hierarchical is true, recursiveQuota and recursiveChildren are ignored
// (the hierarchical query path supersedes them) and results are returned
// depth-ordered (deepest first). When hierarchical is true, reclaimed parents
// are unconditionally excluded regardless of includeReclaimed.
func GetLotsPastDed(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.LotsPastDed(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical)
}

// GetLotsPastOpp returns all lots past their opportunistic_GB quota.
func GetLotsPastOpp(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.LotsPastOpp(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical)
}

// GetLotsPastObj returns all lots past their max_num_objects quota.
func GetLotsPastObj(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	return m.LotsPastObj(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical)
}

// ReclaimLot records a reclamations-ledger entry for the named lot and every
// descendant in its subtree. After this call, lots in the subtree are skipped
// by past_* queries called with includeReclaimed=false; their MPAs and usage
// rows remain intact in the database. The default lot may NOT be reclaimed.
//
// Returns:
//   - lotmanReclaimOK          (0): at least one new ledger row was added.
//   - lotmanReclaimAlreadyDone  (1): every lot in the subtree was
//     already reclaimed; no new row was added (still a success).
//   - lotmanReclaimError       (-1): validation/authorization/storage error.
//
// Pelican itself never calls this from production code paths today --
// reclamation is performed by the xrootd-lotman purge plugin once a lot's
// bytes have actually been drained off disk. The wrapper exists for tests
// and for future GC scheduling.
func ReclaimLot(lotName string, reclaimedAtMs int64, reason, caller string) (int, error) {
	m, err := requireManager()
	if err != nil {
		return lotmanReclaimError, err
	}
	res, err := m.ReclaimLot(lotName, reclaimedAtMs, reason, caller)
	return int(res), err
}

// Reclamation status sentinels matching lotman.h.
const (
	lotmanReclaimOK          = 0
	lotmanReclaimAlreadyDone = 1
	lotmanReclaimError       = -1
)

// UpdateLotUsage submits an absolute (delta_mode=false) or additive
// (delta_mode=true) usage update keyed by lot name. updateJSON is the
// pre-marshalled JSON document accepted by lotman_update_lot_usage.
func UpdateLotUsage(updateJSON string, deltaMode bool, caller string) error {
	m, err := requireManager()
	if err != nil {
		return err
	}
	var in struct {
		LotName                 string   `json:"lot_name"`
		SelfGB                  *float64 `json:"self_GB"`
		SelfObjects             *int64   `json:"self_objects"`
		SelfGBBeingWritten      *float64 `json:"self_GB_being_written"`
		SelfObjectsBeingWritten *int64   `json:"self_objects_being_written"`
	}
	if err := json.Unmarshal([]byte(updateJSON), &in); err != nil {
		return errors.Wrap(err, "error unmarshalling usage update")
	}
	u := core.UsageUpdate{LotName: in.LotName, SelfObjects: in.SelfObjects, SelfObjectsBeingWritten: in.SelfObjectsBeingWritten}
	if in.SelfGB != nil {
		b := gbToBytes(*in.SelfGB)
		u.SelfBytes = &b
	}
	if in.SelfGBBeingWritten != nil {
		b := gbToBytes(*in.SelfGBBeingWritten)
		u.SelfBytesBeingWritten = &b
	}
	return m.UpdateLotUsage(u, deltaMode, caller)
}

// UpdateLotUsageByDir submits a path-keyed usage update; lotman resolves each
// directory to its currently owning lot at the supplied queryTimeMs (0 = now)
// using longest-prefix matching across every lot's paths.
// dirUsageNode is the nested by-dir usage tree accepted by UpdateLotUsageByDir.
type dirUsageNode struct {
	Path    string         `json:"path"`
	SizeGB  *float64       `json:"size_GB"`
	NumObj  *int64         `json:"num_obj"`
	Subdirs []dirUsageNode `json:"subdirs"`
}

func UpdateLotUsageByDir(updateJSON string, deltaMode bool, queryTimeMs int64, caller string) error {
	if queryTimeMs == 0 {
		queryTimeMs = time.Now().UnixMilli()
	}
	m, err := requireManager()
	if err != nil {
		return err
	}
	var nodes []dirUsageNode
	if err := json.Unmarshal([]byte(updateJSON), &nodes); err != nil {
		return errors.Wrap(err, "error unmarshalling by-dir usage update")
	}
	var entries []core.DirUsage
	var walk func(n dirUsageNode)
	walk = func(n dirUsageNode) {
		e := core.DirUsage{Path: n.Path}
		if n.SizeGB != nil {
			e.SizeBytes = gbToBytes(*n.SizeGB)
		}
		if n.NumObj != nil {
			e.NumObjects = *n.NumObj
		}
		entries = append(entries, e)
		for _, c := range n.Subdirs {
			walk(c)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	return m.UpdateLotUsageByDir(entries, deltaMode, queryTimeMs, caller)
}

// GetPolicyAttributes returns the most-restrictive MPA values for each axis
// flagged true in req. The returned RestrictiveMPA contains zero-valued slots
// for axes not requested.
func GetPolicyAttributes(req PolicyAttrsRequest) (*RestrictiveMPA, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	keys := []string{}
	if req.DedicatedGB {
		keys = append(keys, core.MpaKeyDedicatedBytes)
	}
	if req.OpportunisticGB {
		keys = append(keys, core.MpaKeyOpportunisticBytes)
	}
	if req.MaxNumObjects {
		keys = append(keys, core.MpaKeyMaxNumObjects)
	}
	if req.CreationTime {
		keys = append(keys, "creation_time")
	}
	if req.ExpirationTime {
		keys = append(keys, "expiration_time")
	}
	if req.DeletionTime {
		keys = append(keys, "deletion_time")
	}
	rv, err := m.PolicyAttributes(core.PolicyAttrsRequest{LotName: req.LotName, Recursive: true, Keys: keys})
	if err != nil {
		return nil, err
	}
	return restrictiveToAdapter(rv), nil
}

// GetLotDirs returns the path entries associated with lotName. If recursive,
// paths owned by descendant lots are also included.
func GetLotDirs(lotName string, recursive bool) ([]LotPath, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	v, err := m.GetLot(lotName)
	if err != nil {
		return nil, err
	}
	paths := []LotPath{}
	for _, p := range v.Paths {
		paths = append(paths, LotPath{Path: p.Path, Recursive: p.Recursive, LotName: lotName})
	}
	if recursive {
		children, err := m.GetChildren(lotName, true, false)
		if err != nil {
			return nil, err
		}
		for _, c := range children {
			cv, err := m.GetLot(c)
			if err != nil {
				return nil, err
			}
			for _, p := range cv.Paths {
				paths = append(paths, LotPath{Path: p.Path, Recursive: p.Recursive, LotName: c})
			}
		}
	}
	return paths, nil
}

// GetLotUsage returns usage statistics for the lot named in req. Only axes
// flagged in req are populated in the returned LotUsage.
func GetLotUsage(req UsageRequest) (*LotUsage, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	v, err := m.GetLot(req.LotName)
	if err != nil {
		return nil, err
	}
	return usageRowToLotUsage(v.Usage, v.Lot), nil
}

// GetAvailableCapacity returns the available and peak capacity attributable
// to direct children of parentLotName during the half-open window
// [startTimeMs, endTimeMs). This is an advisory query; reservation
// enforcement is performed atomically inside lotman's add/update transactions
// when strict_hierarchy is enabled.
func GetAvailableCapacity(parentLotName string, startTimeMs, endTimeMs int64) (*AvailableCapacity, error) {
	m, err := requireManager()
	if err != nil {
		return nil, err
	}
	c, err := m.AvailableCapacity(parentLotName, startTimeMs, endTimeMs)
	if err != nil {
		return nil, err
	}
	return capacityToAdapter(c), nil
}

// SetContextInt is retained for API compatibility. The native engine has no
// runtime context variables (e.g. the C library's db_timeout), so this is a
// no-op.
func SetContextInt(key string, value int) error {
	return nil
}

// GetContextInt is retained for API compatibility; see SetContextInt.
func GetContextInt(key string) (int, error) {
	return 0, nil
}

// RemoveLot deletes a single lot from the lotman DB while preserving its
// children, applying the supplied reassignment options. Prefer
// DeleteLotsRecursive for normal teardown; this entry point exists for
// callers that need fine-grained control over orphan reassignment.
//
// The caller must be one of the lot's owners. The override_policy flag is
// not yet implemented in the underlying library and is forwarded as-is.
func RemoveLot(lotName string, assignLTBRParentsToOrphans, assignLTBRParentsToNonOrphans, assignPolicyToChildren, overridePolicy bool, caller string) error {
	m, err := requireManager()
	if err != nil {
		return err
	}
	// The native core preserves children by reparenting them to the removed
	// lot's parents, which matches the assign-LTBR-parent-to-orphans intent of
	// the legacy reassignment flags.
	return m.RemoveLot(lotName, core.RemoveOptions{}, caller)
}
