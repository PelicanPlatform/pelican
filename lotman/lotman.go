//go:build !linux || ppc64le

// For now we're shutting off LotMan due to weirdness with purego. When we return to this, remember
// that purego doesn't support (linux && ppc64le), so we'll need to add that back here.
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

// LotMan is only supported on Linux at the moment. This file is a placeholder for other platforms and is
// intended to export any functions that might be called outside of the package
package lotman

import (
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
)

// errUnsupported is returned by every wrapper on non-Linux platforms.
var errUnsupported = errors.New("LotMan is not supported on this platform")

// Minimal re-definition of PurgePolicy so that things compile on non-Linux platforms.
// We may use a different approach someday so we don't need multiple definitions of this struct
// but for now I think this is okay...
type PurgePolicy struct {
	PurgeOrder []string
}

// Type stubs that mirror the linux implementation so cross-platform callers
// can refer to them without a build tag of their own. Field shapes are kept
// minimal -- if a non-Linux caller actually constructs one of these, the
// surrounding wrapper will return errUnsupported anyway.
type (
	MPA               struct{}
	ParentAttribution struct{}
	LotPath           struct{}
	LotUsage          struct{}
	RestrictiveMPA    struct{}
	AvailableCapacity struct{}

	PolicyAttrsRequest struct{ LotName string }
	UsageRequest       struct{ LotName string }
)

func RegisterLotsAPI(router *gin.RouterGroup) error {
	log.Warningln("LotMan is not supported on this platform. Skipping...")
	return nil
}

func InitLotman(adsFromFed []server_structs.NamespaceAdV2) bool {
	log.Warningln("LotMan is not supported on this platform. Skipping...")
	return false
}

func GetPolicyMap() (map[string]PurgePolicy, error) {
	log.Warningln("LotMan is not supported on this platform. Skipping...")
	return map[string]PurgePolicy{}, nil
}

// The following stubs mirror the high-level wrappers added in
// lotman_linux.go so callers compile on non-Linux platforms.

func IsRoot(string) (bool, error)                                     { return false, errUnsupported }
func LotExists(string) (bool, error)                                  { return false, errUnsupported }
func ListAllLots() ([]string, error)                                  { return nil, errUnsupported }
func GetChildrenNames(string, bool, bool) ([]string, error)           { return nil, errUnsupported }
func GetParentNames(string, bool, bool) ([]string, error)             { return nil, errUnsupported }
func GetOwners(string, bool) ([]string, error)                        { return nil, errUnsupported }
func GetLotsFromDir(string, bool, int64) ([]string, error)            { return nil, errUnsupported }
func GetLotsForPath(string, bool, int64, int64, bool) ([]Lot, error)  { return nil, errUnsupported }
func GetLotsPastExp(int64, bool, bool) ([]string, error)              { return nil, errUnsupported }
func GetLotsPastDel(int64, bool, bool) ([]string, error)              { return nil, errUnsupported }
func GetLotsPastDed(bool, bool, bool, bool) ([]string, error)         { return nil, errUnsupported }
func GetLotsPastOpp(bool, bool, bool, bool) ([]string, error)         { return nil, errUnsupported }
func GetLotsPastObj(bool, bool, bool, bool) ([]string, error)         { return nil, errUnsupported }
func ReclaimLot(string, int64, string, string) (int, error)           { return 0, errUnsupported }
func UpdateLotUsage(string, bool, string) error                       { return errUnsupported }
func UpdateLotUsageByDir(string, bool, int64, string) error           { return errUnsupported }
func GetPolicyAttributes(PolicyAttrsRequest) (*RestrictiveMPA, error) { return nil, errUnsupported }
func GetLotDirs(string, bool) ([]LotPath, error)                      { return nil, errUnsupported }
func GetLotUsage(UsageRequest) (*LotUsage, error)                     { return nil, errUnsupported }
func GetAvailableCapacity(string, int64, int64) (*AvailableCapacity, error) {
	return nil, errUnsupported
}
func SetContextInt(string, int) error   { return errUnsupported }
func GetContextInt(string) (int, error) { return 0, errUnsupported }
func RemoveLot(string, bool, bool, bool, bool, string) error {
	return errUnsupported
}
