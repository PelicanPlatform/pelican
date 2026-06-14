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

package lotman

import "github.com/pelicanplatform/pelican/lotman/lotjson"

// The lotman JSON wire schema (Lot/MPA/...) and its conversions to and from the
// byte-based lotman/core model live in the dependency-light lotman/lotjson
// package, so the standalone C-ABI shared library (lotman/cshared) can reuse
// them without importing Pelican. The adapter keeps its original spellings via
// the type aliases and thin shims below; call sites are unchanged.

const bytesInGigabyte = lotjson.BytesInGigabyte

type (
	Int64FromFloat     = lotjson.Int64FromFloat
	LotPath            = lotjson.LotPath
	LotValueMapInt     = lotjson.LotValueMapInt
	LotValueMapFloat   = lotjson.LotValueMapFloat
	MPA                = lotjson.MPA
	ParentAttribution  = lotjson.ParentAttribution
	AvailableCapacity  = lotjson.AvailableCapacity
	PolicyAttrsRequest = lotjson.PolicyAttrsRequest
	UsageRequest       = lotjson.UsageRequest
	RestrictiveMPA     = lotjson.RestrictiveMPA
	UsageMapFloat      = lotjson.UsageMapFloat
	UsageMapInt        = lotjson.UsageMapInt
	LotUsage           = lotjson.LotUsage
	Lot                = lotjson.Lot
	ParentUpdate       = lotjson.ParentUpdate
	PathUpdate         = lotjson.PathUpdate
	LotUpdate          = lotjson.LotUpdate
	LotAddition        = lotjson.LotAddition
	LotPathRemoval     = lotjson.LotPathRemoval
	LotParentRemoval   = lotjson.LotParentRemoval
)

var (
	gbToBytes             = lotjson.GbToBytes
	bytesToGB             = lotjson.BytesToGB
	gbPtrToBytes          = lotjson.GbPtrToBytes
	bytesToGBPtr          = lotjson.BytesToGBPtr
	gbPtrToBytesPtr       = lotjson.GbPtrToBytesPtr
	int64PtrValue         = lotjson.Int64PtrValue
	derefOrZero           = lotjson.DerefOrZero
	pathSpecsFromLotPaths = lotjson.PathSpecsFromLotPaths
	mergeMPAToCore        = lotjson.MergeMPAToCore
	mpaToCore             = lotjson.MpaToCore
	attrValuesToAdapter   = lotjson.AttrValuesToAdapter
	parentAttrToCore      = lotjson.ParentAttrToCore
	lotToSpec             = lotjson.LotToSpec
	coreMPAToAdapter      = lotjson.CoreMPAToAdapter
	lotViewToAdapter      = lotjson.LotViewToAdapter
	splitStorage          = lotjson.SplitStorage
	usageRowToLotUsage    = lotjson.UsageRowToLotUsage
	restrictiveToAdapter  = lotjson.RestrictiveToAdapter
	capacityToAdapter     = lotjson.CapacityToAdapter
)
