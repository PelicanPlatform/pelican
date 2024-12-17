//go:build lotman && linux && !ppc64le

/***************************************************************
*
* Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	LotmanUpdateLot           func(updateJSON string, errMsg *[]byte) int32
	LotmanDeleteLotsRecursive func(lotName string, errMsg *[]byte) int32

	// Auxilliary functions
	LotmanLotExists     func(lotName string, errMsg *[]byte) int32
	LotmanSetContextStr func(contextKey string, contextValue string, errMsg *[]byte) int32
	LotmanGetContextStr func(key string, output *[]byte, errMsg *[]byte) int32
	// Functions that would normally take a char *** as an argument take an *unsafe.Pointer instead because
	// these functions are responsible for allocating and deallocating the memory for the char ***. The Go
	// runtime will handle the memory management for the *unsafe.Pointer.
	LotmanGetLotOwners func(lotName string, recursive bool, output *unsafe.Pointer, errMsg *[]byte) int32
	// Here, getSelf means get the lot proper if it's a self parent
	LotmanGetLotParents  func(lotName string, recursive bool, getSelf bool, output *unsafe.Pointer, errMsg *[]byte) int32
	LotmanGetLotsFromDir func(dir string, recursive bool, output *unsafe.Pointer, errMsg *[]byte) int32
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
		Children *[]string  `json:"children,omitempty"`
		Paths    []LotPath `json:"paths,omitempty" mapstructure:"Paths"`
		MPA      *MPA       `json:"management_policy_attrs,omitempty" mapstructure:"ManagementPolicyAttrs"`
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
		LotName string          `json:"lot_name"`
		Owner   *string         `json:"owner,omitempty"`
		Parents *[]ParentUpdate `json:"parents,omitempty"`
		Paths   *[]PathUpdate   `json:"paths,omitempty"`
		MPA     *MPA            `json:"management_policy_attrs,omitempty"`
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
		return nil, errors.Errorf("Failed to determine %s's parents: %s", lotName, string(errMsg))
	}

	parents := cArrToGoArr(&cParents)

	// Use a map to handle deduplication of owners list
	ownersSet := make(map[string]struct{})
	for _, parent := range parents {
		cOwners := unsafe.Pointer(nil)
		LotmanGetLotOwners(parent, true, &cOwners, &errMsg)
		if ret != 0 {
			trimBuf(&errMsg)
			return nil, errors.Errorf("Failed to determine appropriate owners of %s's parents: %s", lotName, string(errMsg))
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
		federationIssuer = fedInfo.DirectorEndpoint
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
func getPolicyMap() (map[string]PurgePolicy, error) {
	policyMap := make(map[string]PurgePolicy)
	var policies []PurgePolicy
	// Use custom decoder hook to validate fields. This validates all the way down to the bottom of the lot object.
	if err := viper.UnmarshalKey(param.Lotman_PolicyDefinitions.GetName(), &policies, viper.DecodeHook(validateFieldsHook())); err != nil {
		return policyMap, errors.Wrap(err, "error unmarshaling Lotman policy definitions")
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
		// Skip the root lot, which is a container we use to make sure all lots have a federation-owned parent.
		// We don't use the root lot for any other purpose.
		if lot.LotName == "root" {
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
			if lot.MPA.CreationTime == nil || lot.MPA.CreationTime.Value == 0 {
				missingValues = append(missingValues, "ManagementPolicyAttrs.CreationTime")
			}
			if lot.MPA.ExpirationTime == nil || lot.MPA.ExpirationTime.Value == 0 {
				missingValues = append(missingValues, "ManagementPolicyAttrs.ExpirationTime")
			}
			if lot.MPA.DeletionTime == nil || lot.MPA.DeletionTime.Value == 0 {
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
            number, err := strconv.ParseUint(value[:len(value)-1], 10, 64)
            if err != nil {
                return 0, err
            }
            return number * multiplier, nil
        }
    }

    // If no suffix, treat as percentage
    percentage, err := strconv.ParseFloat(strings.TrimSuffix(value, "%"), 64)
    if err != nil {
        return 0, err
    }
    return uint64((percentage / 100) * float64(totalDiskSpace)), nil
}


// Divide the remaining space among lots' dedicatedGB values -- we don't ever want to
// dedicate more space than we have available, as indicated by the HWM of the cache. This is because
// our model is that as long as a lot stays under its dedicated GB, its data is safe in the cache --
// If the sum of each lot's dedicated GB exceeds the HWM, the cache may purge data without a single lot
// exceeding it's quota. BAD!
//
// Opportunistic space can (and should) be overallocated, so unless explicitly set, each lot will have
// dedicatedGB + opportunisticGB = HWM. This isn't maxed out to the total disk space, because otherwise
// no lot could ever exceed its opportunistic storage and we'd lose some of the capabilities to reason about
// how greedy the lot is.
func divideRemainingSpace(lotMap *map[string]Lot, totalDiskSpaceB uint64) error {
	hwmStr := param.Cache_HighWaterMark.GetString()
	if hwmStr == "" {
		return errors.New("high watermark is not set in the cache configuration")
	}
	hwm, err := convertWatermarkToBytes(hwmStr, totalDiskSpaceB)
	if err != nil {
		return errors.Wrap(err, "error converting high watermark to byte value for Lotman")
	}
	remainingToHwmB := hwm

    // first iterate through all lots and subtract from our total space any amount
    // that's already been allocated. Note which lots have an unset value, as we'll
    // need to return to them.
    returnToKeys := make([]string, 0, len(*lotMap))
	for key, lot := range *lotMap {
		if lot.LotName == "root" {
			continue
		}
		if lot.MPA != nil && lot.MPA.DedicatedGB != nil  {
			dedicatedGBBytes := gigabytesToBytes(*lot.MPA.DedicatedGB)
			// While we check that lot config is valid later, we can't finish dividing space if
			// remainintToHwmB dips negative. Can't check for < 0 after subraction because the uint64 will wrap
			if remainingToHwmB < dedicatedGBBytes {
				return errors.New(fmt.Sprintf("the sum of all lots' dedicatedGB values exceeds the high watermark of %s. This would allow the cache to purge namespaces using less than their dedicated quota", hwmStr))
			}
			remainingToHwmB -= dedicatedGBBytes
			if lot.MPA.OpportunisticGB == nil {
				oGb := bytesToGigabytes(hwm) - *lot.MPA.DedicatedGB
				lot.MPA.OpportunisticGB = &oGb
			}
		} else {
			returnToKeys = append(returnToKeys, lot.LotName)
		}
		(*lotMap)[key] = lot
	}

	if len(returnToKeys) > 0 {
		// now iterate through the lots that need space allocated and assign them the
		// remaining space
		spacePerLotRemainingB := remainingToHwmB / uint64(len(returnToKeys))
		for _, key := range returnToKeys {
			lot := (*lotMap)[key]
			if lot.MPA == nil {
				lot.MPA = &MPA{}
			}
			dGb := bytesToGigabytes(spacePerLotRemainingB)
			oGb := bytesToGigabytes(hwm - spacePerLotRemainingB)
			lot.MPA.DedicatedGB = &dGb
			if lot.MPA.OpportunisticGB == nil {
				lot.MPA.OpportunisticGB = &oGb
			}
			lot.MPA.MaxNumObjects = &Int64FromFloat{Value: 0} // Purge plugin doesn't yet use this, set to 0.
			(*lotMap)[key] = lot
		}
	}

	return nil
}

// Lots have unix millisecond timestamps for creation, expiration, and deletion. If these are not set in the
//config, we'll set them to the current time. Expiration and deletion times are set to the default lifetime
func configLotTimestamps(lotMap *map[string]Lot) {
	now := time.Now().UnixMilli()
	defaultExpiration := now + param.Lotman_DefaultLotExpirationLifetime.GetDuration().Milliseconds()
	defaultDeletion := now + param.Lotman_DefaultLotDeletionLifetime.GetDuration().Milliseconds()

	for name, lot := range *lotMap {
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

// By default, Lotman should discover namespaces from the Director and try to create the relevant top-level
// lots for those namespaces. This function creates those lots, but they may be merged with local config
// at a later time.
func configLotsFromFedPrefixes(nsAds []server_structs.NamespaceAdV2) (map[string]Lot, error) {
	directorLotMap := make(map[string]Lot)
	federationIssuer, err := getFederationIssuer()
	if err != nil {
		return directorLotMap, errors.Wrap(err, "Unable to determine federation issuer which is needed by Lotman to determine lot ownership")
	}
	if federationIssuer == "" {
		return directorLotMap, errors.New("The detected federation issuer, which is needed by Lotman to determine lot/namespace ownership, is empty")
	}
	for _, nsAd := range nsAds {
		// Skip monitoring namespaces
		if strings.HasPrefix(nsAd.Path, "/pelican/monitoring") {
			continue
		}
		var issuer string
		if len(nsAd.Issuer) > 0 {
			issuer = (nsAd.Issuer[0]).IssuerUrl.String()
		} else {
			issuer = federationIssuer
		}

		directorLotMap[nsAd.Path] = Lot{
			LotName: nsAd.Path,
			Owner:   issuer, // grab the first issuer -- lotman doesn't currently support multiple direct owners
			// Assign parent as the root lot at the cache. This lets root edit the lot, but still allows the owner of the namespace to further subdivide
			Parents: []string{"root"},
			Paths: []LotPath{
				{
					Path: 	nsAd.Path,
					Recursive: true,
				},
			},
		}
	}

	return directorLotMap, nil
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


// Initialize the lot configurations based on provided policy, discovered namespaces,
// and available cache space, handling any necessary merges and validations along the way.
func initLots(nsAds []server_structs.NamespaceAdV2) ([]Lot, error) {
	var internalLots []Lot

	policies, err := getPolicyMap()
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

	var lotMap map[string]Lot
	if discoverPrefixes {
		directorLotMap, err := configLotsFromFedPrefixes(nsAds)
		if err != nil {
			return internalLots, errors.Wrap(err, "error configuring lots from federation prefixes")
		}

		// Handle potential need to merge discovered namespaces with provided configuration
		if shouldMerge {
			log.Debug("Merging lot configuration from discovered namespaces with configured lots")
			lotMap, err = mergeLotMaps(directorLotMap, policyLotMap)
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

	// Now guarantee our special "default" and "root" lots if the user hasn't provided them
	// in the config. For now, these lots must always exist because they're used to make sure
	// all data is tied to a lot (default) and that the requirement of a root lot is satisfied
	// without allowing discovered lots to gain rootly status.
	federationIssuer, err := getFederationIssuer()
	if err != nil {
		return internalLots, errors.Wrap(err, "Unable to determine the federation's issuer, which is needed by Lotman to determine lot ownership")
	}
	if federationIssuer == "" {
		return internalLots, errors.New("The detected federation issuer, which is needed by Lotman to determine lot/namespace ownership, is empty")
	}
	rootDedGB := bytesToGigabytes(totalDiskSpaceB)
	zero := float64(0)
	if _, exists := lotMap["default"]; !exists {
		lotMap["default"] = Lot{
			LotName: "default",
			Owner:   federationIssuer,
			Parents: []string{"default"},
			MPA: &MPA{
				// Set default values to 0 and let potential reallocation happen later.
				DedicatedGB:     &zero,
				OpportunisticGB: &zero,
				MaxNumObjects:   &Int64FromFloat{Value: 0}, // Purge plugin doesn't yet use this, set to 0.
			},

		}
	}
	if _, exists := lotMap["root"]; !exists {
		lotMap["root"] = Lot{
			LotName: "root",
			Owner:   federationIssuer,
			Parents: []string{"root"},

			Paths: []LotPath{
				{
					Path: 	"/",
					Recursive: false, // setting this to true would prevent any other lot from claiming a path
				},
			},
			MPA: &MPA{
				// Max out dedicatedGB so the root lot never purges. All other lots should be tied to their own policies.
				DedicatedGB: &rootDedGB,
				OpportunisticGB: &zero,
				MaxNumObjects:   &Int64FromFloat{Value: 0}, // Purge plugin doesn't yet use this, set to 0.
			},
		}
	}

	log.Tracef("Lotman will split lot disk space quotas amongst the discovered disk space: %vB", totalDiskSpaceB)
	if policy.DivideUnallocated {
		log.Traceln("Dividing unallocated space among lots")
		divideRemainingSpace(&lotMap, totalDiskSpaceB)
	}

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
	// D
	purego.RegisterLibFunc(&LotmanDeleteLotsRecursive, lotmanLib, "lotman_remove_lots_recursive")

	// Auxilliary functions
	purego.RegisterLibFunc(&LotmanLotExists, lotmanLib, "lotman_lot_exists")
	purego.RegisterLibFunc(&LotmanSetContextStr, lotmanLib, "lotman_set_context_str")
	purego.RegisterLibFunc(&LotmanGetContextStr, lotmanLib, "lotman_get_context_str")
	purego.RegisterLibFunc(&LotmanGetLotOwners, lotmanLib, "lotman_get_owners")
	purego.RegisterLibFunc(&LotmanGetLotParents, lotmanLib, "lotman_get_parent_names")
	purego.RegisterLibFunc(&LotmanGetLotsFromDir, lotmanLib, "lotman_get_lots_from_dir")

	// Set the lot_home context -- where the db lives
	lotHome := param.Lotman_DbLocation.GetString()

	errMsg := make([]byte, 2048)

	log.Infof("Setting lot_home context to %s", lotHome)
	ret := LotmanSetContextStr("lot_home", lotHome, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		log.Errorf("Error setting lot_home context: %s", string(errMsg))
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

	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret = LotmanSetContextStr("caller", federationIssuer, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		log.Errorf("Error setting caller context to %s for default lot: %s", federationIssuer, string(errMsg))
		return false
	}

	// Create the basic lots if they don't already exist. We'll make one for default
	// and one for the root namespace
	defaultInitialized := false
	ret = LotmanLotExists("default", &errMsg)
	if ret < 0 {
		trimBuf(&errMsg)
		log.Errorf("Error checking if default lot exists: %s", string(errMsg))
		return false
	} else if ret == 0 {
		for _, lot := range initializedLots {
			if lot.LotName == "default" {
				log.Debugf("Creating the default lot defined by %v", lot)
				lotJSON, err := json.Marshal(lot)
				if err != nil {
					log.Errorf("Error marshalling default lot JSON: %v", err)
					return false
				}

				ret = LotmanAddLot(string(lotJSON), &errMsg)
				if ret != 0 {
					trimBuf(&errMsg)
					log.Errorf("Error creating default lot: %s", string(errMsg))
					return false
				}
				defaultInitialized = true
			}
		}

		log.Infof("Created default lot")
	} else if ret == 1 {
		log.Infoln("Default lot already exists, skipping creation")
	}

	rootInitialized := false
	ret = LotmanLotExists("root", &errMsg)
	if ret < 0 {
		trimBuf(&errMsg)
		log.Errorf("Error checking if root lot exists: %s", string(errMsg))
		return false
	} else if ret == 0 {
		for _, lot := range initializedLots {
			if lot.LotName == "root" {
				lotJSON, err := json.Marshal(lot)
				if err != nil {
					log.Errorf("Error marshalling root lot JSON: %v", err)
					return false
				}

				ret = LotmanAddLot(string(lotJSON), &errMsg)
				if ret != 0 {
					trimBuf(&errMsg)
					log.Errorf("Error creating root lot: %s", string(errMsg))
					return false
				}
				rootInitialized = true
			}
		}

		log.Infof("Created root lot")
	} else if ret == 1 {
		log.Infoln("Root lot already exists, skipping creation")
	}

	if !defaultInitialized || !rootInitialized {
		log.Errorln("Failed to create default and/or root lots")
		return false
	}

	// Now instantiate any other lots that are in the config
	for _, lot := range initializedLots {
		if lot.LotName != "default" && lot.LotName != "root" {
			// Don't try to re-create lots that may already exist, as doing so could prevent
			// the cache from restarting.
			// TODO: Work out how to handle this case -- we may need to update the lot instead of creating it
			ret = LotmanLotExists(lot.LotName, &errMsg)
			if ret < 0 {
				trimBuf(&errMsg)
				log.Errorf("Error checking if lot '%s'exists: %s", lot.LotName, string(errMsg))
				return false
			} else if ret == 0 {
				lotJSON, err := json.Marshal(lot)
				if err != nil {
					log.Errorf("Error marshalling lot JSON for %s: %v", lot.LotName, err)
					return false
				}

				ret = LotmanAddLot(string(lotJSON), &errMsg)
				if ret != 0 {
					trimBuf(&errMsg)
					log.Errorf("Error creating lot %s: %s", lot.LotName, string(errMsg))
					log.Infoln("Full lot JSON passed to Lotman for lot creation:", string(lotJSON))
					return false
				}
			} else if ret == 1 {
				log.Infof("Lot '%s' already exists, skipping creation", lot.LotName)
			} else {
				log.Errorf("Unexpected return value from Lotman for lot '%s' existence check: %d", lot.LotName, ret)
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
	// Marshal the JSON into a string for the C function
	lotJSON, err := json.Marshal(*newLot)
	if err != nil {
		return errors.Wrapf(err, "Error marshalling lot JSON: %v", err)
	}

	// Set the context to the incoming lot's owner:
	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf(fmt.Sprintf("Error creating lot: %s", string(errMsg)))
	}

	// Now finally add the lot
	ret = LotmanAddLot(string(lotJSON), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf(fmt.Sprintf("Error creating lot: %s", string(errMsg)))
	}

	return nil
}

// Given a lot name, get the lot from the lot database. If recursive is true, we'll also
// determine all hierarchical restrictions on the lot. For example, if the lot "foo" has
// dedicated_GB = 2.0 but its parent lot "bar" has dedicated_GB = 1.0, then calling this
// with recusrive = true will indicate the restricting value and the lot it comes from.
func GetLot(lotName string, recursive bool) (*Lot, error) {
	// Haven't given much thought to these buff sizes yet
	outputBuf := make([]byte, 4096)
	errMsg := make([]byte, 2048)

	ret := LotmanGetLotJSON(lotName, recursive, &outputBuf, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return nil, errors.Errorf("Error getting lot JSON: %s", string(errMsg))
	}
	trimBuf(&outputBuf)
	var lot Lot
	err := json.Unmarshal(outputBuf, &lot)
	if err != nil {
		return nil, errors.Wrapf(err, "Error unmarshalling lot JSON: %v", err)
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
	// Marshal the JSON into a string for the C function
	updateJSON, err := json.Marshal(*lotUpdate)
	if err != nil {
		return errors.Wrapf(err, "Error marshalling lot JSON: %v", err)
	}

	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	ret := LotmanSetContextStr("caller", caller, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf(fmt.Sprintf("Error setting caller for lot update: %s", string(errMsg)))
	}

	ret = LotmanUpdateLot(string(updateJSON), &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf(fmt.Sprintf("Error updating lot: %s", string(errMsg)))
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
		return fmt.Errorf(fmt.Sprintf("Error creating lot: %s", string(errMsg)))
	}

	// We've set the caller, now try to delete the lots
	ret = LotmanDeleteLotsRecursive(lotName, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return fmt.Errorf(fmt.Sprintf("Error deleting lots: %s", string(errMsg)))
	}

	return nil
}
