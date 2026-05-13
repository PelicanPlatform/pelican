//go:build linux && !ppc64le

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"golang.org/x/mod/semver"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	// A mutex for the Lotman caller context -- make sure we're calling lotman functions with the appropriate caller
	callerMutex = sync.RWMutex{}

	initializedLots []Lot

	// Lotman func signatures we'll bind to the underlying C headers
	LotmanVersion func() string
	// Strings in go are immutable, so they're actually passed to the underlying SO as `const`. To get dynamic
	// output, we need to pass a pointer to a byte array
	LotmanAddLot              func(lotJSON string, errMsg *[]byte) int32
	LotmanGetLotJSON          func(lotName string, recursive bool, output *[]byte, errMsg *[]byte) int32
	LotmanAddToLot            func(additionsJSON string, errMsg *[]byte) int32
	LotmanRemoveLotParents    func(removalsJSON string, errMsg *[]byte) int32
	LotmanRemoveLotPaths      func(removalsJSON string, errMsg *[]byte) int32
	LotmanUpdateLot           func(updateJSON string, errMsg *[]byte) int32
	LotmanDeleteLotsRecursive func(lotName string, errMsg *[]byte) int32

	// Auxiliary functions
	LotmanLotExists     func(lotName string, errMsg *[]byte) int32
	LotmanIsRoot        func(lotName string, errMsg *[]byte) int32
	LotmanSetContextStr func(contextKey string, contextValue string, errMsg *[]byte) int32
	LotmanGetContextStr func(key string, output *[]byte, errMsg *[]byte) int32
	LotmanSetContextInt func(contextKey string, contextValue int32, errMsg *[]byte) int32
	LotmanGetContextInt func(key string, output *int32, errMsg *[]byte) int32
	// Functions that would normally take a char *** as an argument take an *unsafe.Pointer instead because
	// these functions are responsible for allocating and deallocating the memory for the char ***. The Go
	// runtime will handle the memory management for the *unsafe.Pointer.
	LotmanGetLotOwners func(lotName string, recursive bool, output *unsafe.Pointer, errMsg *[]byte) int32
	// Here, getSelf means get the lot proper if it's a self parent
	LotmanGetLotParents  func(lotName string, recursive bool, getSelf bool, output *unsafe.Pointer, errMsg *[]byte) int32
	LotmanGetLotChildren func(lotName string, recursive bool, getSelf bool, output *unsafe.Pointer, errMsg *[]byte) int32
	LotmanGetLotsFromDir func(dir string, recursive bool, queryTimeMs int64, output *unsafe.Pointer, errMsg *[]byte) int32
	LotmanListAllLots    func(output *unsafe.Pointer, errMsg *[]byte) int32
	// Window-aware variant of lotman_get_lots_from_dir (lotman PR #52). Returns a
	// JSON array of full lot objects (same shape as lotman_get_lot_as_json with
	// recursive=false) for every lot that wins the longest-prefix path-resolution
	// contest at any instant in the half-open window [timeLoMs, timeHiMs). Used
	// by the renewal scheduler to enumerate just the lots that touch a given
	// namespace path during the planning window, replacing the O(all lots)
	// listAllLotsFull walk.
	LotmanGetLotsForPath func(path string, recursive bool, timeLoMs int64, timeHiMs int64, includeReclaimed bool, output *[]byte, errMsg *[]byte) int32
	// past_exp/past_del signatures gained a leading `int64 query_time` in lotman
	// PR #52 to let callers reason about future or past states of the ledger
	// (preview which lots will be expired/deletable by some timestamp). Pass
	// wall-clock now() in milliseconds for the historical "as of now" semantics.
	// `include_reclaimed` was added in v0.0.5+; cleanup loops should pass false
	// to avoid repeatedly draining lots that have already been reclaimed.
	LotmanGetLotsPastExp func(queryTimeMs int64, recursive bool, includeReclaimed bool, output *unsafe.Pointer, errMsg *[]byte) int32
	LotmanGetLotsPastDel func(queryTimeMs int64, recursive bool, includeReclaimed bool, output *unsafe.Pointer, errMsg *[]byte) int32
	LotmanGetLotsPastDed func(recursiveQuota bool, recursiveChildren bool, includeReclaimed bool, output *unsafe.Pointer, hierarchical bool, errMsg *[]byte) int32
	LotmanGetLotsPastOpp func(recursiveQuota bool, recursiveChildren bool, includeReclaimed bool, output *unsafe.Pointer, hierarchical bool, errMsg *[]byte) int32
	LotmanGetLotsPastObj func(recursiveQuota bool, recursiveChildren bool, includeReclaimed bool, output *unsafe.Pointer, hierarchical bool, errMsg *[]byte) int32

	// Reclamation ledger (lotman v0.0.5+). LotmanReclaimLot records that the
	// caller (typically the purge plugin) is no longer attributing bytes to
	// the named lot subtree; downstream past_* queries with
	// include_reclaimed=false ignore reclaimed lots.
	LotmanReclaimLot func(lotName string, reclaimedAtMs int64, reason string, errMsg *[]byte) int32

	// Usage update entry points. Both accept a delta_mode bool: when false,
	// the supplied JSON describes ABSOLUTE current usage (preferred); when
	// true, it describes additive deltas. Pelican (and the purge plugin)
	// always pass delta_mode=false so that on-disk state is the source of
	// truth and missed updates self-heal on the next reporting tick.
	LotmanUpdateLotUsage      func(updateJSON string, deltaMode bool, errMsg *[]byte) int32
	LotmanUpdateLotUsageByDir func(updateJSON string, deltaMode bool, queryTimeMs int64, errMsg *[]byte) int32

	// Functions returning a single JSON document via char **
	LotmanGetPolicyAttributes  func(requestJSON string, output *[]byte, errMsg *[]byte) int32
	LotmanGetLotDirs           func(lotName string, recursive bool, output *[]byte, errMsg *[]byte) int32
	LotmanGetLotUsage          func(requestJSON string, output *[]byte, errMsg *[]byte) int32
	LotmanGetAvailableCapacity func(parentLotName string, startTimeMs int64, endTimeMs int64, output *[]byte, errMsg *[]byte) int32

	// Lot deletion preserving children (vs. recursive delete)
	LotmanRemoveLot func(lotName string, assignLTBRParentsToOrphans bool, assignLTBRParentsToNonOrphans bool, assignPolicyToChildren bool, overridePolicy bool, errMsg *[]byte) int32

	// Free a char ** allocated by lotman.
	LotmanFreeStringList func(strList unsafe.Pointer)
)

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

// Convert a cArray to a Go slice of strings. The cArray is a null-terminated
// array of null-terminated strings.
func cArrToGoArr(cArr *unsafe.Pointer) []string {
	ptr := uintptr(*cArr)
	var goArr []string
	for {
		// Read the uintptr at the current position.
		strPtr := *(*uintptr)(unsafe.Pointer(ptr))

		// Break if the uintptr is null.
		if strPtr == 0 {
			break
		}

		// Create a Go string from the null-terminated string.
		goStr := ""
		for i := 0; ; i++ {
			// Read the byte at the current position.
			b := *(*byte)(unsafe.Pointer(strPtr + uintptr(i)))

			// Break if the byte is null.
			if b == 0 {
				break
			}

			// Append the byte to the Go string.
			goStr += string(b)
		}

		// Append the Go string to the slice.
		goArr = append(goArr, goStr)

		// Move to the next uintptr.
		ptr += unsafe.Sizeof(uintptr(0))
	}

	return goArr
}

// Trim any buffer we get back from LotMan to the first null char
func trimBuf(buf *[]byte) {
	// Find the index of the first null character
	nullIndex := bytes.IndexByte(*buf, 0)

	// Trim the slice after the first null character
	if nullIndex != -1 {
		*buf = (*buf)[:nullIndex]
	}
}

// Use the detected runtime to predict the location of the LotMan library.
func getLotmanLib() string {
	fallbackPaths := []string{
		"/usr/lib64/libLotMan.so",
		"/usr/local/lib64/libLotMan.so",
		"/opt/local/lib64/libLotMan.so",
	}

	switch runtime.GOOS {
	case "linux":
		configuredPath := param.Lotman_LibLocation.GetString()
		if configuredPath != "" {
			if _, err := os.Stat(configuredPath); err == nil {
				return configuredPath
			}
			log.Errorln("libLotMan.so not found in configured path, attempting to find using known fallbacks")
		}

		for _, path := range fallbackPaths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		panic("libLotMan.so not found in any of the known paths")
	default:
		panic(fmt.Errorf("GOOS=%s is not supported", runtime.GOOS))
	}
}

func GetAuthorizedCallers(lotName string) (*[]string, error) {
	// A caller is authorized if they own a parent of the lot. In the case of self-parenting lots, the owner is authorized.
	errMsg := make([]byte, 2048)
	cParents := unsafe.Pointer(nil)

	// Get immediate parents (including self to determine rootliness). We'll use them to determine owners
	// who are allowed to manipulate, and thus delete, the lot
	ret := LotmanGetLotParents(lotName, false, true, &cParents, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("failed to determine %s's parents: %s", lotName, string(errMsg))
	}

	parents := cArrToGoArr(&cParents)

	// Use a map to handle deduplication of owners list
	ownersSet := make(map[string]struct{})
	for _, parent := range parents {
		cOwners := unsafe.Pointer(nil)
		LotmanGetLotOwners(parent, true, &cOwners, &errMsg)
		if ret != 0 {
			trimBuf(&errMsg)
			return nil, errors.Errorf("failed to determine appropriate owners of %s's parents: %s", lotName, string(errMsg))
		}

		for _, owner := range cArrToGoArr(&cOwners) {
			ownersSet[owner] = struct{}{}
		}
	}

	// Convert the keys of the map to a slice
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

// Given a filesystem path, try to get the amount of total and free disk space.
func getDiskUsage(path string) (total uint64, free uint64, err error) {
	var stat syscall.Statfs_t

	err = syscall.Statfs(path, &stat)
	if err != nil {
		return 0, 0, err
	}

	// Total space is the block size multiplied by the total number of blocks
	total = stat.Blocks * uint64(stat.Bsize)

	// Free space is the block size multiplied by the number of free blocks
	free = stat.Bfree * uint64(stat.Bsize)

	return total, free, nil
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
		// root and default carry the all-zero non-expiring sentinel introduced
		// in lotman PR #44. Skip them so their timestamps are not overwritten
		// with real values by the defaulting logic below.
		if lot.LotName == "root" || lot.LotName == "default" {
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
func updateLotIfNeeded(existingLot *Lot, newLot *Lot, caller string) error {
	lotUpdate, lotAddition, lotPathRemoval, lotParentRemoval, err := getLotUpdateJSONs(existingLot, newLot)
	if err != nil {
		return errors.Wrap(err, "error getting lot update JSONs")
	}

	// Send our update objects to Lotman
	if lotUpdate != nil {
		if err := UpdateLot(lotUpdate, caller); err != nil {
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
func ensureLotExistsOrUpdate(lotName string, initializedLots []Lot, federationIssuer string) (bool, error) {
	errMsg := make([]byte, 2048)
	ret := LotmanLotExists(lotName, &errMsg)
	if ret < 0 {
		trimBuf(&errMsg)
		log.Errorf("Unable to check whether %s lot exists: %s", lotName, string(errMsg))
		return false, fmt.Errorf("unable to check whether %s lot exists: %s", lotName, string(errMsg))
	}

	if ret == 0 {
		// Lot does not exist, create it
		for _, lot := range initializedLots {
			if lot.LotName == lotName {
				log.Debugf("Creating lot %s defined by %v", lotName, lot)

				// Validate that none of the paths have a trailing / -- while I'd argue Lotman
				// should handle this, it breaks things as of Lotman v0.0.4 and causes all lot
				// usage to show up as belonging to the default lot.
				for _, path := range lot.Paths {
					if lotName != "root" {
						strings.TrimSuffix(path.Path, "/")
					}
				}

				lotJSON, err := json.Marshal(lot)
				if err != nil {
					log.Errorf("Unable to marshal %s lot JSON: %v", lotName, err)
					return false, fmt.Errorf("unable to marshal %s lot JSON: %v", lotName, err)
				}

				ret = LotmanAddLot(string(lotJSON), &errMsg)
				if ret != 0 {
					trimBuf(&errMsg)
					log.Errorf("Unable to create lot %s: %s", lotName, string(errMsg))
					return false, fmt.Errorf("unable to create lot %s: %s", lotName, string(errMsg))
				}
				log.Infof("Created lot %s", lotName)
				return true, nil
			}
		}
	} else if ret == 1 {
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

				err = updateLotIfNeeded(existingLot, &lot, federationIssuer)
				if err != nil {
					log.Errorf("Unable to update lot %s: %v", lotName, err)
					return false, fmt.Errorf("unable to update lot %s: %v", lotName, err)
				}
				return true, nil
			}
		}
	}

	return false, nil
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
		defOpp := zero
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

// setLotmanContextFlags installs the strict-hierarchy execution context that
// the new lotman library uses to enforce parent/child quota and time-window
// axioms. Must be called after `lot_home` is set but before any lots are
// created/queried so the flags apply to subsequent transactions.
//
// The flags are:
//   - strict_hierarchy=true: every non-root child must declare
//     parent_attributions for every non-self parent, and the recursive
//     allocator's invariants (axioms 1, 2, 3) are enforced on add/update.
//   - contraction_policy=always: refuse any update that contracts a lot's
//     MPAs (the strictest of lotman's three options 'none', 'alive', 'always')
//     unless `admin_override=true` is also set.
//   - admin_override=false: do not bypass policy checks by default.
func setLotmanContextFlags() error {
	errMsg := make([]byte, 2048)
	flags := []struct {
		key, value string
	}{
		{"strict_hierarchy", "true"},
		{"contraction_policy", "always"},
		{"admin_override", "false"},
	}
	for _, f := range flags {
		ret := LotmanSetContextStr(f.key, f.value, &errMsg)
		if ret != 0 {
			trimBuf(&errMsg)
			return errors.Errorf("error setting lotman context %q to %q: %s", f.key, f.value, string(errMsg))
		}
	}
	return nil
}

// minLotmanVersion is the earliest lotman release that exposes every
// FFI symbol Pelican's lotman integration registers below. Bump this
// whenever a new symbol is added to InitLotman.
const minLotmanVersion = "v0.0.5"

// checkLotmanVersionCompatibility returns true when the loaded libLotMan.so
// is new enough to support Pelican's strict-hierarchy lot layout, and false
// (with a logged error) when it is not.  It uses the semver package so the
// comparison is correct for any future minor/patch bump.
func checkLotmanVersionCompatibility() bool {
	v := LotmanVersion()
	if !semver.IsValid(v) {
		log.Errorf("lotman_version() returned an unrecognised version string %q; "+
			"cannot verify compatibility. Require lotman >= %s.", v, minLotmanVersion)
		return false
	}
	if semver.Compare(v, minLotmanVersion) < 0 {
		log.Errorf("Installed lotman version %s is too old; Pelican requires lotman >= %s. "+
			"Please upgrade libLotMan.so and restart.", v, minLotmanVersion)
		return false
	}
	return true
}

// Initialize the LotMan library and bind its functions to the global vars
// We also perform a bit of extra setup such as setting the lotman db location
func InitLotman(adsFromFed []server_structs.NamespaceAdV2) bool {
	log.Infof("Initializing LotMan...")

	// dlopen the LotMan library
	lotmanLib, err := purego.Dlopen(getLotmanLib(), purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		log.Errorf("Error opening LotMan library: %v", err)
		return false
	}

	// Register LotMan funcs
	purego.RegisterLibFunc(&LotmanVersion, lotmanLib, "lotman_version")
	// C
	purego.RegisterLibFunc(&LotmanAddLot, lotmanLib, "lotman_add_lot")
	// R
	purego.RegisterLibFunc(&LotmanGetLotJSON, lotmanLib, "lotman_get_lot_as_json")
	// U
	purego.RegisterLibFunc(&LotmanUpdateLot, lotmanLib, "lotman_update_lot")
	purego.RegisterLibFunc(&LotmanAddToLot, lotmanLib, "lotman_add_to_lot")
	purego.RegisterLibFunc(&LotmanRemoveLotParents, lotmanLib, "lotman_rm_parents_from_lot")
	purego.RegisterLibFunc(&LotmanRemoveLotPaths, lotmanLib, "lotman_rm_paths_from_lots")
	// D
	purego.RegisterLibFunc(&LotmanDeleteLotsRecursive, lotmanLib, "lotman_remove_lots_recursive")

	// Auxiliary functions
	purego.RegisterLibFunc(&LotmanLotExists, lotmanLib, "lotman_lot_exists")
	purego.RegisterLibFunc(&LotmanIsRoot, lotmanLib, "lotman_is_root")
	purego.RegisterLibFunc(&LotmanSetContextStr, lotmanLib, "lotman_set_context_str")
	purego.RegisterLibFunc(&LotmanGetContextStr, lotmanLib, "lotman_get_context_str")
	purego.RegisterLibFunc(&LotmanSetContextInt, lotmanLib, "lotman_set_context_int")
	purego.RegisterLibFunc(&LotmanGetContextInt, lotmanLib, "lotman_get_context_int")
	purego.RegisterLibFunc(&LotmanGetLotOwners, lotmanLib, "lotman_get_owners")
	purego.RegisterLibFunc(&LotmanGetLotParents, lotmanLib, "lotman_get_parent_names")
	purego.RegisterLibFunc(&LotmanGetLotChildren, lotmanLib, "lotman_get_children_names")
	purego.RegisterLibFunc(&LotmanGetLotsFromDir, lotmanLib, "lotman_get_lots_from_dir")
	purego.RegisterLibFunc(&LotmanGetLotsForPath, lotmanLib, "lotman_get_lots_for_path")
	purego.RegisterLibFunc(&LotmanListAllLots, lotmanLib, "lotman_list_all_lots")
	purego.RegisterLibFunc(&LotmanGetLotsPastExp, lotmanLib, "lotman_get_lots_past_exp")
	purego.RegisterLibFunc(&LotmanGetLotsPastDel, lotmanLib, "lotman_get_lots_past_del")
	purego.RegisterLibFunc(&LotmanGetLotsPastDed, lotmanLib, "lotman_get_lots_past_ded")
	purego.RegisterLibFunc(&LotmanGetLotsPastOpp, lotmanLib, "lotman_get_lots_past_opp")
	purego.RegisterLibFunc(&LotmanGetLotsPastObj, lotmanLib, "lotman_get_lots_past_obj")
	purego.RegisterLibFunc(&LotmanReclaimLot, lotmanLib, "lotman_reclaim_lot")
	purego.RegisterLibFunc(&LotmanUpdateLotUsage, lotmanLib, "lotman_update_lot_usage")
	purego.RegisterLibFunc(&LotmanUpdateLotUsageByDir, lotmanLib, "lotman_update_lot_usage_by_dir")
	purego.RegisterLibFunc(&LotmanGetPolicyAttributes, lotmanLib, "lotman_get_policy_attributes")
	purego.RegisterLibFunc(&LotmanGetLotDirs, lotmanLib, "lotman_get_lot_dirs")
	purego.RegisterLibFunc(&LotmanGetLotUsage, lotmanLib, "lotman_get_lot_usage")
	purego.RegisterLibFunc(&LotmanGetAvailableCapacity, lotmanLib, "lotman_get_available_capacity")
	purego.RegisterLibFunc(&LotmanRemoveLot, lotmanLib, "lotman_remove_lot")
	purego.RegisterLibFunc(&LotmanFreeStringList, lotmanLib, "lotman_free_string_list")

	// Create the lot home dir (where lotman's sqlite db lives) and set the lot_home context
	lotHome := param.Lotman_LotHome.GetString()
	uid, err := config.GetDaemonUID()
	if err != nil {
		log.Errorf("Error getting daemon UID, needed to create '%s' directory: %v", param.Lotman_LotHome.GetName(), err)
		return false
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		log.Errorf("Error getting daemon GID, needed to create '%s' directory: %v", param.Lotman_LotHome.GetName(), err)
		return false
	}
	err = config.MkdirAll(lotHome, 0777, uid, gid)
	if err != nil {
		log.Errorf("Error creating lot home directory: %v", err)
		return false
	}

	errMsg := make([]byte, 2048)

	log.Infof("Setting lot_home context to %s", lotHome)
	ret := LotmanSetContextStr("lot_home", lotHome, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		log.Errorf("Error setting lot_home context: %s", string(errMsg))
		return false
	}

	// Enable strict_hierarchy + contraction_policy=strict + admin_override=false
	// before any lot creation so the new lotman schema's invariants are
	// enforced from the very first add_lot call.
	if err := setLotmanContextFlags(); err != nil {
		log.Errorf("Error setting lotman context flags: %v", err)
		return false
	}

	// Verify the installed libLotMan.so is >= minLotmanVersion before
	// creating any lots.
	if !checkLotmanVersionCompatibility() {
		return false
	}

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

	// Encapsulate the lock/unlock -- strange things can happen when you call into the underlying C
	func() {
		callerMutex.Lock()
		defer callerMutex.Unlock()
		ret = LotmanSetContextStr("caller", federationIssuer, &errMsg)
	}()
	if ret != 0 {
		trimBuf(&errMsg)
		log.Errorf("Error setting caller context to %s for default lot: %s", federationIssuer, string(errMsg))
		return false
	}

	// Init/update the default lot, which must exist _before_ any other lots can be touched
	defaultInitialized, err := ensureLotExistsOrUpdate("default", initializedLots, federationIssuer)
	if err != nil {
		return false
	}

	// Init/update the root lot, which is a container we use to make sure all lots have a federation-owned parent.
	rootInitialized, err := ensureLotExistsOrUpdate("root", initializedLots, federationIssuer)
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
			initialized, err := ensureLotExistsOrUpdate(lot.LotName, initializedLots, federationIssuer)
			if err != nil {
				return false
			}
			if !initialized {
				log.Errorf("Failed to initialize lot %s", lot.LotName)
				return false
			}
		}
	}

	// We've created the lotman home directory, but the database lotman creates will still be
	// owned by the uid:gid that started the cache. Recursively set ownership to XRootD, but set
	// permissions such that the Pelican user can still modify it.
	if err := filepath.WalkDir(filepath.Join(lotHome, ".lot"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return errors.Wrapf(err, "the path %s cannot be accessed", path)
		}
		if chmodErr := os.Chmod(path, 0777); chmodErr != nil {
			return errors.Wrapf(chmodErr, "permissions on the path %s to Lotman's database cannot be set", path)
		}
		if chownErr := os.Chown(path, uid, gid); chownErr != nil {
			return errors.Wrapf(chownErr, "ownership of the path %s to Lotman's database cannot be set", path)
		}

		return nil
	}); err != nil {
		log.Errorf("Unable to finalize Lotman's initialization: %v", err)
		return false
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
	// Marshal the JSON into a string for the C function
	lotJSON, err := json.Marshal(*newLot)
	if err != nil {
		return errors.Wrap(err, "error marshalling lot JSON")
	}

	// Set the context to the incoming lot's owner:
	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error creating lot: %s", string(errMsg))
	}

	// Now finally add the lot
	ret = LotmanAddLot(string(lotJSON), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error creating lot: %s", string(errMsg))
	}

	return nil
}

// Given a lot name, get the lot from the lot database. If recursive is true, we'll also
// determine all hierarchical restrictions on the lot. For example, if the lot "foo" has
// dedicated_GB = 2.0 but its parent lot "bar" has dedicated_GB = 1.0, then calling this
// with recursive = true will indicate the restricting value and the lot it comes from.
func GetLot(lotName string, recursive bool) (*Lot, error) {
	// Haven't given much thought to these buff sizes yet
	outputBuf := make([]byte, 4096)
	errMsg := make([]byte, 2048)

	ret := LotmanGetLotJSON(lotName, recursive, &outputBuf, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting lot JSON: %s", string(errMsg))
	}
	trimBuf(&outputBuf)
	var lot Lot
	err := json.Unmarshal(outputBuf, &lot)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshalling lot JSON")
	}
	return &lot, nil
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
	// Marshal the JSON into a string for the C function
	updateJSON, err := json.Marshal(*lotUpdate)
	if err != nil {
		return errors.Wrap(err, "error marshalling lot JSON")
	}

	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error setting caller for lot update: %s", string(errMsg))
	}

	ret = LotmanUpdateLot(string(updateJSON), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error updating lot: %s", string(errMsg))
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
	additionsJSON, err := json.Marshal(*lotAddition)
	if err != nil {
		return errors.Wrap(err, "error marshalling lot addition JSON")
	}

	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error setting caller for lot update: %s", string(errMsg))
	}

	ret = LotmanAddToLot(string(additionsJSON), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error adding to lot: %s", string(errMsg))
	}

	return nil
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
	// Marshal the JSON into a string for the C function
	parentRemovalJSON, err := json.Marshal(*parentsRemoval)
	if err != nil {
		return errors.Wrap(err, "error marshalling lot parents removal JSON")
	}

	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error setting caller for lot parents removal: %s", string(errMsg))
	}

	ret = LotmanRemoveLotParents(string(parentRemovalJSON), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error adding removing parents from lot: %s", string(errMsg))
	}

	return nil
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
	// Marshal the JSON into a string for the C function
	pathRemovalJSON, err := json.Marshal(*pathsRemoval)
	if err != nil {
		return errors.Wrap(err, "error marshalling lot paths removal JSON")
	}

	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error setting caller for lot paths removal: %s", string(errMsg))
	}

	ret = LotmanRemoveLotPaths(string(pathRemovalJSON), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error adding removing paths from lot: %s", string(errMsg))
	}

	return nil
}

// Delete a lot from the lot database. The caller is the entity that is deleting the lot, and is used to determine
// whether we want to allow the deletion to go through. In general, a valid caller is one that matches an owner from
// any of the lot's recursive parents. This function deletes the lot and all of its children.
func DeleteLotsRecursive(lotName string, caller string) error {
	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error creating lot: %s", string(errMsg))
	}

	// We've set the caller, now try to delete the lots. Under
	// contraction_policy=always, deletion is treated as contraction-to-zero
	// and is blocked unless admin_override=true. Pelican-internal teardown
	// is by definition admin-driven, so flip the flag for the duration of
	// this call. callerMutex is already held above, which serialises the
	// admin_override toggle as well.
	if ret = LotmanSetContextStr("admin_override", "true", &errMsg); ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error enabling admin_override for deletion: %s", string(errMsg))
	}
	defer func() {
		restoreErr := make([]byte, 2048)
		_ = LotmanSetContextStr("admin_override", "false", &restoreErr)
	}()
	ret = LotmanDeleteLotsRecursive(lotName, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf("error deleting lots: %s", string(errMsg))
	}

	return nil
}

// drainStringList copies the contents of a lotman char** output into a Go
// slice and frees the underlying C allocation. Safe to call on a nil pointer.
func drainStringList(p *unsafe.Pointer) []string {
	if p == nil || *p == nil {
		return nil
	}
	out := cArrToGoArr(p)
	LotmanFreeStringList(*p)
	*p = nil
	return out
}

// IsRoot reports whether lotName names a root lot (only self-parent).
func IsRoot(lotName string) (bool, error) {
	errMsg := make([]byte, 2048)
	ret := LotmanIsRoot(lotName, &errMsg)
	if ret < 0 {
		trimBuf(&errMsg)
		return false, errors.Errorf("error checking root status of %s: %s", lotName, string(errMsg))
	}
	return ret == 1, nil
}

// LotExists reports whether a lot with the given name exists in the lotman DB.
func LotExists(lotName string) (bool, error) {
	errMsg := make([]byte, 2048)
	ret := LotmanLotExists(lotName, &errMsg)
	if ret < 0 {
		trimBuf(&errMsg)
		return false, errors.Errorf("error checking existence of lot %s: %s", lotName, string(errMsg))
	}
	return ret == 1, nil
}

// ListAllLots returns every lot name currently stored in the lotman DB.
func ListAllLots() ([]string, error) {
	errMsg := make([]byte, 2048)
	out := unsafe.Pointer(nil)
	ret := LotmanListAllLots(&out, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error listing lots: %s", string(errMsg))
	}
	return drainStringList(&out), nil
}

// GetChildrenNames returns the names of lotName's children. If recursive is
// true, all transitive descendants are returned. If getSelf is true, lotName
// is included when it self-parents.
func GetChildrenNames(lotName string, recursive, getSelf bool) ([]string, error) {
	errMsg := make([]byte, 2048)
	out := unsafe.Pointer(nil)
	ret := LotmanGetLotChildren(lotName, recursive, getSelf, &out, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting children of %s: %s", lotName, string(errMsg))
	}
	return drainStringList(&out), nil
}

// GetParentNames returns the names of lotName's parents. If recursive is
// true, all transitive ancestors are returned.
func GetParentNames(lotName string, recursive, getSelf bool) ([]string, error) {
	errMsg := make([]byte, 2048)
	out := unsafe.Pointer(nil)
	ret := LotmanGetLotParents(lotName, recursive, getSelf, &out, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting parents of %s: %s", lotName, string(errMsg))
	}
	return drainStringList(&out), nil
}

// GetOwners returns the owner identities recorded for lotName. If recursive
// is true, owners of all ancestor lots are unioned in.
func GetOwners(lotName string, recursive bool) ([]string, error) {
	errMsg := make([]byte, 2048)
	out := unsafe.Pointer(nil)
	ret := LotmanGetLotOwners(lotName, recursive, &out, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting owners of %s: %s", lotName, string(errMsg))
	}
	return drainStringList(&out), nil
}

// GetLotsFromDir returns the names of lots tracking the supplied path at the
// supplied wall-clock time (Unix milliseconds). queryTimeMs of 0 means "now".
// If recursive is true, every parent lot is also returned. The result is
// non-empty for every legal input: paths not tied to any lot resolve to the
// "default" lot.
func GetLotsFromDir(dir string, recursive bool, queryTimeMs int64) ([]string, error) {
	if queryTimeMs == 0 {
		queryTimeMs = time.Now().UnixMilli()
	}
	errMsg := make([]byte, 2048)
	out := unsafe.Pointer(nil)
	ret := LotmanGetLotsFromDir(dir, recursive, queryTimeMs, &out, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting lots for path %s: %s", dir, string(errMsg))
	}
	return drainStringList(&out), nil
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
	// 64 KiB is generous; a typical query returns 2-5 lots × ~1 KiB each.
	// trimBuf scans for the trailing null terminator so an oversized buffer
	// is harmless.
	output := make([]byte, 65536)
	errMsg := make([]byte, 2048)
	ret := LotmanGetLotsForPath(path, recursive, timeLoMs, timeHiMs, includeReclaimed, &output, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting lots for path %s in window [%d, %d): %s", path, timeLoMs, timeHiMs, string(errMsg))
	}
	trimBuf(&output)
	var lots []Lot
	if err := json.Unmarshal(output, &lots); err != nil {
		return nil, errors.Wrapf(err, "error unmarshalling lots-for-path JSON for %s", path)
	}
	return lots, nil
}

// pastLotsHelper centralises the past-quota query pattern.
func pastLotsHelper(name string, fn func(*unsafe.Pointer, *[]byte) int32) ([]string, error) {
	errMsg := make([]byte, 2048)
	out := unsafe.Pointer(nil)
	ret := fn(&out, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error querying %s: %s", name, string(errMsg))
	}
	return drainStringList(&out), nil
}

// GetLotsPastExp returns all lots past their expiration_time relative to
// the supplied queryTimeMs cutoff (a Unix timestamp in milliseconds). Pass
// time.Now().UnixMilli() for the historical "as of now" semantics; pass a
// future timestamp to preview which lots will be expired by then. If
// recursive, the most-restricting ancestor expiration_time is used.
// If includeReclaimed is false (the typical cleanup-loop value) lots with
// a reclamations-ledger row whose reclaimed_at <= queryTimeMs are excluded.
func GetLotsPastExp(queryTimeMs int64, recursive, includeReclaimed bool) ([]string, error) {
	return pastLotsHelper("lots-past-exp", func(out *unsafe.Pointer, errMsg *[]byte) int32 {
		return LotmanGetLotsPastExp(queryTimeMs, recursive, includeReclaimed, out, errMsg)
	})
}

// GetLotsPastDel returns all lots past their deletion_time relative to the
// supplied queryTimeMs cutoff. See GetLotsPastExp for the meaning of
// queryTimeMs and includeReclaimed.
func GetLotsPastDel(queryTimeMs int64, recursive, includeReclaimed bool) ([]string, error) {
	return pastLotsHelper("lots-past-del", func(out *unsafe.Pointer, errMsg *[]byte) int32 {
		return LotmanGetLotsPastDel(queryTimeMs, recursive, includeReclaimed, out, errMsg)
	})
}

// GetLotsPastDed returns all lots past their dedicated_GB quota.
// When hierarchical is true, recursiveQuota and recursiveChildren are ignored
// (the hierarchical query path supersedes them) and results are returned
// depth-ordered (deepest first). When hierarchical is true, reclaimed parents
// are unconditionally excluded regardless of includeReclaimed.
func GetLotsPastDed(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	return pastLotsHelper("lots-past-ded", func(out *unsafe.Pointer, errMsg *[]byte) int32 {
		return LotmanGetLotsPastDed(recursiveQuota, recursiveChildren, includeReclaimed, out, hierarchical, errMsg)
	})
}

// GetLotsPastOpp returns all lots past their opportunistic_GB quota.
func GetLotsPastOpp(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	return pastLotsHelper("lots-past-opp", func(out *unsafe.Pointer, errMsg *[]byte) int32 {
		return LotmanGetLotsPastOpp(recursiveQuota, recursiveChildren, includeReclaimed, out, hierarchical, errMsg)
	})
}

// GetLotsPastObj returns all lots past their max_num_objects quota.
func GetLotsPastObj(recursiveQuota, recursiveChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	return pastLotsHelper("lots-past-obj", func(out *unsafe.Pointer, errMsg *[]byte) int32 {
		return LotmanGetLotsPastObj(recursiveQuota, recursiveChildren, includeReclaimed, out, hierarchical, errMsg)
	})
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
	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return lotmanReclaimError, errors.Errorf("error setting caller for lot reclamation: %s", string(errMsg))
	}
	ret = LotmanReclaimLot(lotName, reclaimedAtMs, reason, &errMsg)
	if ret == lotmanReclaimError {
		trimBuf(&errMsg)
		return lotmanReclaimError, errors.Errorf("error reclaiming lot %s: %s", lotName, string(errMsg))
	}
	return int(ret), nil
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
	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error setting caller for usage update: %s", string(errMsg))
	}
	ret = LotmanUpdateLotUsage(updateJSON, deltaMode, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error updating lot usage: %s", string(errMsg))
	}
	return nil
}

// UpdateLotUsageByDir submits a path-keyed usage update; lotman resolves each
// directory to its currently owning lot at the supplied queryTimeMs (0 = now)
// using longest-prefix matching across every lot's paths.
func UpdateLotUsageByDir(updateJSON string, deltaMode bool, queryTimeMs int64, caller string) error {
	if queryTimeMs == 0 {
		queryTimeMs = time.Now().UnixMilli()
	}
	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error setting caller for by-dir usage update: %s", string(errMsg))
	}
	ret = LotmanUpdateLotUsageByDir(updateJSON, deltaMode, queryTimeMs, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error updating lot usage by dir: %s", string(errMsg))
	}
	return nil
}

// GetPolicyAttributes returns the most-restrictive MPA values for each axis
// flagged true in req. The returned RestrictiveMPA contains zero-valued slots
// for axes not requested.
func GetPolicyAttributes(req PolicyAttrsRequest) (*RestrictiveMPA, error) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling policy-attributes request")
	}
	errMsg := make([]byte, 2048)
	output := make([]byte, 4096)
	ret := LotmanGetPolicyAttributes(string(reqJSON), &output, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting policy attributes for %s: %s", req.LotName, string(errMsg))
	}
	trimBuf(&output)
	var rmpa RestrictiveMPA
	if err := json.Unmarshal(output, &rmpa); err != nil {
		return nil, errors.Wrapf(err, "error unmarshalling policy-attributes response %q", string(output))
	}
	return &rmpa, nil
}

// GetLotDirs returns the path entries associated with lotName. If recursive,
// paths owned by descendant lots are also included.
func GetLotDirs(lotName string, recursive bool) ([]LotPath, error) {
	errMsg := make([]byte, 2048)
	output := make([]byte, 4096)
	ret := LotmanGetLotDirs(lotName, recursive, &output, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting paths for %s: %s", lotName, string(errMsg))
	}
	trimBuf(&output)
	var paths []LotPath
	if err := json.Unmarshal(output, &paths); err != nil {
		return nil, errors.Wrapf(err, "error unmarshalling lot-dirs response %q", string(output))
	}
	return paths, nil
}

// GetLotUsage returns usage statistics for the lot named in req. Only axes
// flagged in req are populated in the returned LotUsage.
func GetLotUsage(req UsageRequest) (*LotUsage, error) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling usage request")
	}
	errMsg := make([]byte, 2048)
	output := make([]byte, 4096)
	ret := LotmanGetLotUsage(string(reqJSON), &output, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting usage for %s: %s", req.LotName, string(errMsg))
	}
	trimBuf(&output)
	var usage LotUsage
	if err := json.Unmarshal(output, &usage); err != nil {
		return nil, errors.Wrapf(err, "error unmarshalling usage response %q", string(output))
	}
	return &usage, nil
}

// GetAvailableCapacity returns the available and peak capacity attributable
// to direct children of parentLotName during the half-open window
// [startTimeMs, endTimeMs). This is an advisory query; reservation
// enforcement is performed atomically inside lotman's add/update transactions
// when strict_hierarchy is enabled.
func GetAvailableCapacity(parentLotName string, startTimeMs, endTimeMs int64) (*AvailableCapacity, error) {
	errMsg := make([]byte, 2048)
	output := make([]byte, 4096)
	ret := LotmanGetAvailableCapacity(parentLotName, startTimeMs, endTimeMs, &output, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("error getting available capacity for %s: %s", parentLotName, string(errMsg))
	}
	trimBuf(&output)
	var ac AvailableCapacity
	if err := json.Unmarshal(output, &ac); err != nil {
		return nil, errors.Wrapf(err, "error unmarshalling available-capacity response %q", string(output))
	}
	return &ac, nil
}

// SetContextInt sets an integer-valued lotman context variable (e.g. db_timeout).
func SetContextInt(key string, value int) error {
	errMsg := make([]byte, 2048)
	ret := LotmanSetContextInt(key, int32(value), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error setting lotman context int %s=%d: %s", key, value, string(errMsg))
	}
	return nil
}

// GetContextInt reads an integer-valued lotman context variable.
func GetContextInt(key string) (int, error) {
	errMsg := make([]byte, 2048)
	var out int32
	ret := LotmanGetContextInt(key, &out, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return 0, errors.Errorf("error getting lotman context int %s: %s", key, string(errMsg))
	}
	return int(out), nil
}

// RemoveLot deletes a single lot from the lotman DB while preserving its
// children, applying the supplied reassignment options. Prefer
// DeleteLotsRecursive for normal teardown; this entry point exists for
// callers that need fine-grained control over orphan reassignment.
//
// The caller must be one of the lot's owners. The override_policy flag is
// not yet implemented in the underlying library and is forwarded as-is.
func RemoveLot(lotName string, assignLTBRParentsToOrphans, assignLTBRParentsToNonOrphans, assignPolicyToChildren, overridePolicy bool, caller string) error {
	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error setting caller for lot removal: %s", string(errMsg))
	}
	// Same admin_override dance as DeleteLotsRecursive: contraction_policy
	// blocks single-lot removal too unless admin_override=true.
	if ret = LotmanSetContextStr("admin_override", "true", &errMsg); ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error enabling admin_override for lot removal: %s", string(errMsg))
	}
	defer func() {
		restoreErr := make([]byte, 2048)
		_ = LotmanSetContextStr("admin_override", "false", &restoreErr)
	}()
	ret = LotmanRemoveLot(lotName, assignLTBRParentsToOrphans, assignLTBRParentsToNonOrphans, assignPolicyToChildren, overridePolicy, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return errors.Errorf("error removing lot %s: %s", lotName, string(errMsg))
	}
	return nil
}
