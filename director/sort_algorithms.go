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

package director

import (
	"cmp"
	"fmt"
	"math/rand"
	"slices"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	// Struct that lets us map a weight to the index of the server ad it came from
	SwapMap struct {
		Weight float64
		Index  int
	}

	SwapMaps []SwapMap

	weightError struct {
		NegIdxs []int
	}
)





const (
	// Various constants used in weight calculations
	distanceHalvingFactor = 200  // Halving distance for the GeoIP weight, in miles
	objAvailabilityFactor = 2.0  // Multiplier for knowing whether an object is present
	loadHalvingThreshold  = 10.0 // Threshold where the load halving factor kicks in
	loadHalvingFactor     = 4.0  // Halving interval for load
)

func (me SwapMaps) Len() int {
	return len(me)
}

func (me SwapMaps) Less(left, right int) bool {
	return me[left].Weight < me[right].Weight
}

func (me SwapMaps) Swap(left, right int) {
	me[left], me[right] = me[right], me[left]
}

// Given a swap map, filter out any entries with zero or negative weights,
// returning the indices of any entries with negative weights -- these constitute
// errors and can be used by calling functions to determine which server ads
// are generating illegal weights.
func (me *SwapMaps) FilterZeroAndNegWeights() (negWeightIdxs []int) {
	nonZeros := 0
	for _, s := range *me {
		if s.Weight > 0 {
			(*me)[nonZeros] = s
			nonZeros++
		} else if s.Weight < 0 {
			negWeightIdxs = append(negWeightIdxs, s.Index)
		}
	}
	*me = (*me)[:nonZeros]

	return
}

// Given a SwapMaps, sort it in descending order by weight
// Function named with "sm" prefix to avoid confusion with sort methods
// on server ads.
func (sm *SwapMaps) smSortDescending() *weightError {
	if len(*sm) == 0 {
		return nil
	}

	// Perform a zero/neg weight filter before we sort
	negWeightIdxs := sm.FilterZeroAndNegWeights()

	slices.SortStableFunc(*sm, func(a, b SwapMap) int {
		return cmp.Compare(b.Weight, a.Weight)
	})

	if len(negWeightIdxs) > 0 {
		return &weightError{NegIdxs: negWeightIdxs}
	}
	return nil
}

// Given a SwapMaps struct, stochasticlly sort the weights based on the following procedure:
//
//  1. Create ranges [0, weight_1), [weight_1, weight_1 + weight_2), ... for each weight.
//
//  2. Select a random number in the range [0, sum(weights)).
//
//  3. If the number falls within the range corresponding to the weight, it is sorted to the top.
//
//  4. Remove the range corresponding to the selected weight and re-calculate the ranges.
//
//  5. Repeat step 2-4 to select the rest weights
//
// NOTE: Assumes all weights are non-negative and remove any that aren't.
// Function named with "sm" prefix to avoid confusion with sort methods
// on server ads.
func (sms *SwapMaps) smSortStochastic() *weightError {
	if len(*sms) == 0 {
		return nil
	}

	// Perform a zero/neg weight filter before we sort
	negWeightIdxs := sms.FilterZeroAndNegWeights()

	n := len(*sms)
	for i := 0; i < n-1; i++ {
		// Compute the sum of weights for the remaining unsorted part
		var wSum float64
		for j := i; j < n; j++ {
			wSum += (*sms)[j].Weight
		}

		// Pick a random number in [0, wSum)
		ranNum := rand.Float64() * wSum
		var acc float64
		var pick int
		for j := i; j < n; j++ {
			acc += (*sms)[j].Weight
			if ranNum < acc {
				pick = j
				break
			}
		}
		// Swap the picked element to the current position
		(*sms)[i], (*sms)[pick] = (*sms)[pick], (*sms)[i]
	}

	if len(negWeightIdxs) > 0 {
		return &weightError{NegIdxs: negWeightIdxs}
	}

	return nil
}

// Given a sort algorithm and a SwapMaps that apply to the indeces of a slice of server ads,
// return a new slice of server ads sorted by the weights in the SwapMaps.
func (sm SwapMaps) GetSortedAds(ads []server_structs.ServerAd, sType smSortType) []server_structs.ServerAd {
	switch sType {
	case smSortDescending:
		if weightError := sm.smSortDescending(); weightError != nil {
			log.Errorf("Error during descending sort: %s; these servers have been filtered for this request", weightError.Error(ads))
		}
	case smSortStochastic:
		if weightError := sm.smSortStochastic(); weightError != nil {
			log.Errorf("Error during stochastic sort: %s; these servers have been filtered for this request", weightError.Error(ads))
		}
	}

	result := make([]server_structs.ServerAd, len(sm)) // len(sm) <= len(ads) because we may have filtered out some ads with bad weights
	for i, w := range sm {
		result[i] = ads[w.Index]
	}
	return result
}

/////////////////////
// SORT ALGORITHMS //
/////////////////////

/*
	These sort algorithms are end-to-end sort algorithms for slices of server ads.

	They each take an input slice of server ads and a SortContext (which holds other
	algorithm inputs) and return a slice of server ads sorted according to the algorithm.
	They should not modify the input slice.
*/

type SortAlgorithm interface {
	Sort(sAds []server_structs.ServerAd, sCtx SortContext) ([]server_structs.ServerAd, error)
	Type() server_structs.SortType
	String() string
}

type smSortType int

const (
	smSortDescending smSortType = iota
	smSortStochastic
)

// Sort a list of ServerAds with the following rule:
//   - if a ServerAds has FromTopology = true, then it will be moved to the end of the list
//   - if two ServerAds has the SAME FromTopology value (both true or false), then break tie them by name
func sortServerAdsByTopo(ads []*server_structs.Advertisement) {
	slices.SortStableFunc(ads, func(a, b *server_structs.Advertisement) int {
		if a.FromTopology && !b.FromTopology {
			return 1
		} else if !a.FromTopology && b.FromTopology {
			return -1
		} else {
			return cmp.Compare(a.Name, b.Name)
		}
	})
}

// Stable-sort the given serveAds in-place given the availMap, where the key of the map is serverAd.Url.String()
// and the value is a bool suggesting if the server has the object requested.
//
// Smaller index in the sorted array means higher priority
func sortServerAdsByAvailability(ads []server_structs.ServerAd, availMap map[string]bool) {
	slices.SortStableFunc(ads, func(a, b server_structs.ServerAd) int {
		if !availMap[a.URL.String()] && availMap[b.URL.String()] {
			return 1
		} else if availMap[a.URL.String()] && !availMap[b.URL.String()] {
			return -1
		} else {
			// Preserve original ordering
			return 0
		}
	})
}
