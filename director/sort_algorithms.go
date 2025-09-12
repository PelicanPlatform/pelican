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

// An error type that indicates which server ads generated negative weights,
// used with various sort algorithms implemented on SwapMaps. The returned
// indices are used to determine which server ads are generating illegal weights.
func (we weightError) Error(sAds []server_structs.ServerAd) string {
	if len(we.NegIdxs) == 0 {
		return ""
	}

	if len(sAds) == 0 {
		return "Some servers generated negative weights, but no server ads were provided to identify them"
	}

	// Look up which server ads generated negative SM weights and log the error
	serverUrls := []string{}
	for _, idx := range we.NegIdxs {
		if idx >= 0 && idx < len(sAds) {
			serverUrls = append(serverUrls, sAds[idx].URL.String())
		} else {
			serverUrls = append(serverUrls, fmt.Sprintf("index %d out of range [0,%d]", idx, len(sAds)-1))
		}
	}

	return fmt.Sprintf("The following servers generated negative weights, which should not be possible and indicates an internal bug: %v", serverUrls)
}

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

// Given a sort algorithm and a SwapMaps that apply to the indices of a slice of server ads,
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

/////////////////////////
// WEIGHT CALCULATIONS //
/////////////////////////

/*
	Each weight fn should return two values -- a float64 weight and a bool indicating
	whether the weight float should be considered valid. If the bool is false, some
	input to the weight function was invalid (e.g. negative load, missing coordinates)
	and the weight should be ignored. A weight fn should never return a negative weight.

	These weight fns are then called in `computeWeights`, which has the extra task of
	imputing median values for missing data.
*/

// Get an exponential decay weight based on the distance between two coordinates.
// The weight starts at 1.0 for zero distance and halves every halvingFactor miles by
// using the formula: weight = 2^(-d/hf) where d is the distance and hf is the halving factor.
func distanceWeight(lat1 float64, long1 float64, lat2 float64, long2 float64) (weight float64) {
	return thresholdedExponentialHalvingMultiplier(angularDistanceOnSphere(lat1, long1, lat2, long2)*earthRadiusToMilesFactor, 0, distanceHalvingFactor)
}

// Returns a distance-based weight (larger = better).
// Returns ok=false if server coordinates are missing.
// The input client coordinate should always be valid because getClientCoordinate
// always returns something, but we still check it.
func distanceWeightFn(clientLat, clientLon, serverLat, serverLon float64) (float64, bool) {
	if serverLat == 0 && serverLon == 0 {
		return 0, false
	}

	if clientLat == 0 && clientLon == 0 {
		return 0, false
	}

	w := distanceWeight(clientLat, clientLon, serverLat, serverLon)
	if w < 0 { // guard against negative weights
		return 0, false
	}
	return w, true
}

// Converts server IO load into a weight (larger = better).
// Weights start at 1.0 up until the threshold is reached, then halve every halvingFactor units of load.
//
// Note: Not currently known whether these input values are upper-bounded, which could cause an
// underflow that results in a zero weight. This is probably okay because we wouldn't want to send
// anyone to that server anyway.
func ioLoadWeight(load float64) (weight float64) {
	return thresholdedExponentialHalvingMultiplier(load, loadHalvingThreshold, loadHalvingFactor)
}

// Converts server IO load into a weight (larger = better).
// Returns ok=false if load is invalid.
func ioLoadWeightFn(load float64) (float64, bool) {
	if load < 0 {
		return 0, false
	}
	w := ioLoadWeight(load)
	if w < 0 { // guard against negative weights
		return 0, false
	}

	return w, true
}

// Uses the server’s status weight field directly, if valid (0–1 range).
// Returns ok=false if status weight is outside valid range.
func statusWeightFn(sw float64) (float64, bool) {
	if sw <= 0 || sw > 1 {
		return 0, false
	}
	return sw, true
}

// Calculates availability weight based on the availability map.
// Returns ok=false if the map has no entry for this server so median imputation can happen
func availabilityWeightFn(ad server_structs.ServerAd, availMap map[string]bool, availFactor float64) (float64, bool) {
	if availFactor <= 0 { // invalid factor
		return 0, false
	}
	if availMap == nil {
		// no information for _any_ objects --> neutral weights for all
		return 1.0, true
	}

	avail, ok := availMap[ad.Name]
	if !ok {
		return 0, false
	}
	if avail {
		return availFactor, true
	}
	return 1 / availFactor, true
}

/////////////////////////////
// END WEIGHT CALCULATIONS //
/////////////////////////////

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

// A simple sort that randomizes the order of the server ads.
type RandomSort struct{}

func (rs *RandomSort) Type() server_structs.SortType {
	return server_structs.RandomType
}
func (rs *RandomSort) String() string {
	return string(server_structs.RandomType)
}

// RandomSort doesn't actually use the SortContext, but it's part of the interface
func (rs *RandomSort) Sort(sAds []server_structs.ServerAd, _ SortContext) ([]server_structs.ServerAd, error) {
	copyAds := make([]server_structs.ServerAd, len(sAds))
	copy(copyAds, sAds)
	// Shuffle the copy, not the original
	rand.Shuffle(len(copyAds), func(i, j int) {
		copyAds[i], copyAds[j] = copyAds[j], copyAds[i]
	})
	return copyAds, nil
}

// Sort server ads according to client/server distance.
// If the client's location is not known, a bounded random client location is used.
// If a server's location is not known, the median distance of all known servers is imputed.
// This has the effect of placing servers with unknown location in the middle of the sorted list.
type DistanceSort struct{}

func (rs *DistanceSort) Type() server_structs.SortType {
	return server_structs.DistanceType
}
func (rs *DistanceSort) String() string {
	return string(server_structs.DistanceType)
}
func (ds *DistanceSort) Sort(sAds []server_structs.ServerAd, sCtx SortContext) ([]server_structs.ServerAd, error) {
	// getClientCoordinate is guaranteed to give us _some_ coordinate, even if it's random.
	clientCoord := getClientCoordinate(sCtx.Ctx, sCtx.ClientAddr)
	sCtx.RedirectInfo.ClientInfo.Coordinate = clientCoord

	dWeights := computeWeights(sAds, func(_ int, ad server_structs.ServerAd) (float64, bool) {
		return distanceWeightFn(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude)
	})

	sCtx.RedirectInfo.ServersInfo = make(map[string]*server_structs.ServerRedirectInfo)
	for idx, w := range dWeights {
		// populate the RedirectInfo
		thisServer := &server_structs.ServerRedirectInfo{}
		thisServer.RedirectWeights.DistanceWeight = w.Weight
		thisServer.Coordinate = sAds[idx].Coordinate
		url := sAds[idx].URL.String()
		sCtx.RedirectInfo.ServersInfo[url] = thisServer
	}

	return dWeights.GetSortedAds(sAds, smSortDescending), nil
}

// An adaptive sort that combines multiple factors: distance, IO load, status weight, and availability.
// See:
//   - https://github.com/PelicanPlatform/pelican/discussions/1198
//   - https://docs.google.com/document/d/1w-1oUhFTN6QN_PfQ5qbS7uf8Su3K8q6MZD3TGLKTHB8/edit?tab=t.0
type AdaptiveSort struct{}

func (rs *AdaptiveSort) Type() server_structs.SortType {
	return server_structs.AdaptiveType
}
func (rs *AdaptiveSort) String() string {
	return string(server_structs.AdaptiveType)
}
func (as *AdaptiveSort) Sort(sAds []server_structs.ServerAd, sCtx SortContext) ([]server_structs.ServerAd, error) {
	clientCoord := getClientCoordinate(sCtx.Ctx, sCtx.ClientAddr)
	sCtx.RedirectInfo.ClientInfo.Coordinate = clientCoord

	// Helper function to template computing weights and storing them
	// in the appropriate field of the adaptiveSortServerWeights struct.
	applyWeights := func(
		label string,
		sAds []server_structs.ServerAd,
		serverWeights []*server_structs.RedirectWeights,
		weightFn func(int, server_structs.ServerAd) (float64, bool),

		// Once weights are generated, this function applies them to the appropriate field
		// in the server weights struct
		applyFn func(wStruct *server_structs.RedirectWeights, w float64),
	) error {
		weights := computeWeights(sAds, weightFn)

		if len(weights) != len(serverWeights) {
			return fmt.Errorf("calculating %s weights: got %d, expected %d",
				label, len(weights), len(serverWeights))
		}

		for _, w := range weights {
			if w.Index >= len(serverWeights) {
				return fmt.Errorf("calculating %s weights: index %d out of range [0,%d]",
					label, w.Index, len(serverWeights)-1)
			}

			// Apply the weight to the appropriate field of the serverWeights struct
			applyFn(serverWeights[w.Index], w.Weight)
		}
		return nil
	}

	// Sort first by distance -- we'll only keep the top sourceWorkingSetSize ads
	// from this sort to use for the rest of the algorithm
	dWeights := computeWeights(sAds, func(_ int, ad server_structs.ServerAd) (float64, bool) {
		return distanceWeightFn(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude)
	})

	dWeights.smSortDescending()

	// Shrink down to the working set size
	shrinkTo := min(sourceWorkingSetSize, len(dWeights))
	dWeights = dWeights[:shrinkTo]
	workingSet := dWeights.GetSortedAds(sAds, smSortDescending)

	// build aligned weights slice
	serverWeights := make([]*server_structs.RedirectWeights, len(workingSet))
	for i := range workingSet {
		serverWeights[i] = &server_structs.RedirectWeights{
			DistanceWeight: dWeights[i].Weight,
		}
	}

	// NOTE: The following three goroutines all write to different fields of the same
	// serverWeights slice, so there should be no race conditions. If you need to add a
	// new goroutine that writes to serverWeights, be very careful to ensure it doesn't
	// write to the same fields as another goroutine.
	errGrp, _ := errgroup.WithContext(sCtx.Ctx)

	// ioLoad weights
	errGrp.Go(func() error {
		return applyWeights("ioLoad", workingSet, serverWeights,
			func(_ int, ad server_structs.ServerAd) (float64, bool) {
				return ioLoadWeightFn(ad.IOLoad)
			},
			func(sw *server_structs.RedirectWeights, w float64) { sw.IOLoadWeight = w },
		)
	})

	// status weights
	errGrp.Go(func() error {
		return applyWeights("status", workingSet, serverWeights,
			func(_ int, ad server_structs.ServerAd) (float64, bool) {
				return statusWeightFn(ad.StatusWeight)
			},
			func(sw *server_structs.RedirectWeights, w float64) { sw.StatusWeight = w },
		)
	})

	// availability weights
	errGrp.Go(func() error {
		return applyWeights("availability", workingSet, serverWeights,
			func(_ int, ad server_structs.ServerAd) (float64, bool) {
				return availabilityWeightFn(ad, sCtx.AvailabilityMap, objAvailabilityFactor)
			},
			func(sw *server_structs.RedirectWeights, w float64) { sw.AvailabilityWeight = w },
		)
	})

	if err := errGrp.Wait(); err != nil {
		return nil, err
	}

	// Final weights from each raw weight
	sCtx.RedirectInfo.ServersInfo = make(map[string]*server_structs.ServerRedirectInfo)
	finalWeights := make(SwapMaps, len(workingSet))
	for idx, weights := range serverWeights {
		finalWeight := weights.DistanceWeight * weights.IOLoadWeight * weights.StatusWeight * weights.AvailabilityWeight
		finalWeights[idx] = SwapMap{finalWeight, idx}

		// populate the RedirectInfo
		thisServer := &server_structs.ServerRedirectInfo{}
		thisServer.RedirectWeights = *weights
		thisServer.Coordinate = workingSet[idx].Coordinate
		url := workingSet[idx].URL.String()
		sCtx.RedirectInfo.ServersInfo[url] = thisServer
	}

	return finalWeights.GetSortedAds(workingSet, smSortStochastic), nil
}

///////////////////////////
// OTHER MISC SORT STUFF //
///////////////////////////

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
