//go:build !windows && !darwin

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

package lotman

import (
	"bytes"
	"encoding/json"
	"fmt"

	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	// "github.com/lestrrat-go/jwx/v2/jwa"
	// "github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	// A mutex for the Lotman caller context -- make sure we're calling lotman functions with the appropriate caller
	callerMutex = sync.RWMutex{}

	// Global vars used for one-time Lotman lib initialization
	lotmanInitTried   = false
	lotmanInitSuccess = false

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
		Value int64
	}

	LotPaths struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
		LotName   string `json:"lot_name,omitempty"`
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
		DedicatedGB     *float64        `json:"dedicated_GB,omitempty"`
		OpportunisticGB *float64        `json:"opportunistic_GB,omitempty"`
		MaxNumObjects   *Int64FromFloat `json:"max_num_objects,omitempty"`
		CreationTime    *Int64FromFloat `json:"creation_time,omitempty"`
		ExpirationTime  *Int64FromFloat `json:"expiration_time,omitempty"`
		DeletionTime    *Int64FromFloat `json:"deletion_time,omitempty"`
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
		LotName        string          `json:"lot_name"`
		Owner          string          `json:"owner,omitempty"`
		Owners         []string        `json:"owners,omitempty"`
		Parents        []string        `json:"parents"`
		Children       *[]string       `json:"children,omitempty"`
		Paths          []LotPaths      `json:"paths,omitempty"`
		MPA            *MPA            `json:"management_policy_attrs,omitempty"`
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
	switch runtime.GOOS {
	// case "darwin":
	// 	return "calc.dylib"
	case "linux":
		return "/usr/lib64/libLotMan.so"
	default:
		panic(fmt.Errorf("GOOS=%s is not supported", runtime.GOOS))
	}
}

func getAuthorizedCallers(lotName string) (*[]string, error) {
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

	owners := []string{}
	internalOwners := []string{}
	for _, parent := range parents {
		fmt.Printf("Parent: %s\n", string(parent))

		cOwners := unsafe.Pointer(nil)
		LotmanGetLotOwners(parent, true, &cOwners, &errMsg)
		if ret != 0 {
			trimBuf(&errMsg)
			return nil, errors.Errorf("Failed to determine appropriate owners of %s's parents: %s", lotName, string(errMsg))
		}

		internalOwners = append(internalOwners, cArrToGoArr(&cOwners)...)
	}

	// Deduplicate the owners
	occurred := map[string]bool{}
	for e := range internalOwners {
		if !occurred[internalOwners[e]] {
			occurred[internalOwners[e]] = true
			owners = append(owners, internalOwners[e])
		}
	}

	return &owners, nil
}

// Given a token and a list of authorized callers, check that the token is signed by one of the authorized callers. Return
// a pointer to the parsed token.
func tokenSignedByAuthorizedCaller(strToken string, authorizedCallers *[]string) (bool, *jwt.Token, error) {
	ownerFound := false
	var tok jwt.Token
	for _, owner := range *authorizedCallers {
		kSet, err := utils.GetJWKSFromIssUrl(owner)
		if err != nil {
			log.Debugf("Error getting JWKS for owner %s: %v", owner, err)
			continue
		}
		tok, err = jwt.Parse([]byte(strToken), jwt.WithKeySet(*kSet), jwt.WithValidate(true))
		if err != nil {
			log.Debugf("Token verification failed with owner %s: %v -- skipping", owner, err)
			continue
		}
		ownerFound = true
		break
	}

	if !ownerFound {
		return false, nil, errors.New("token not signed by any of the owners of any parent lot")
	}

	return true, &tok, nil
}

// Verify that a token received is a valid token. Upon verification, we set the lot's parents/owner to the
// appropriate values. Returns true if the token is valid, false otherwise.
func VerifyNewLotToken(lot *Lot, strToken string) (bool, error) {
	tokenApproved := false

	// Get the path associated with the lot (right now we assume/enforce a single path) and try
	// to deduce a namespace prefix from that. We'll use that namespace prefix's issuer as the
	// owner of the lot. If there is no associated isuer, we assign ownership to the federation

	path := ((lot.Paths)[0]).Path
	log.Debugf("Attempting to add lot for path: %s", path)
	errMsg := make([]byte, 2048)
	lots := unsafe.Pointer(nil)
	// Pass a pointer to the first element of the slice to the C++ function.
	ret := LotmanGetLotsFromDir(path, false, &lots, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return false, errors.Errorf("Error getting lot JSON: %s", string(errMsg))
	}

	goLots := cArrToGoArr(&lots)

	// Check if goOut[0] is "default". Lotman should ALWAYS put something in this array. If it's empty, we have a problem.
	if goLots[0] == "default" {
		// We'll assign to the root lot. However, be careful here because we make an assumption -- under the hood,
		// Lotman will return "default" if there's no other lot, or if the actual path is in some way assigned to
		// the default lot. When we assign to parent to root here, we're assuming the former. This implies we should stay
		// away from assigning paths to the default lot.
		lot.Parents = []string{"root"}
	} else {
		// We found a different logical parent
		lot.Parents = goLots
	}

	var tok jwt.Token
	if len(lot.Parents) == 0 && lot.Parents[0] == "root" {
		// We check that the token is signed by the federation
		// First check for discovery URL and then for director URL, both of which should host the federation's pubkey
		issuerUrl := param.Federation_DiscoveryUrl.GetString()
		if issuerUrl == "" {
			issuerUrl = param.Federation_DirectorUrl.GetString()
			if issuerUrl == "" {
				return false, errors.New("Federation discovery URL and director URL are not set")
			}
			log.Debugln("Federation discovery URL is not set, using director URL as lot token issuer")
		}

		kSet, err := utils.GetJWKSFromIssUrl(issuerUrl)
		if err != nil {
			return false, errors.Wrap(err, "Error getting JWKS from issuer URL")
		}

		tok, err = jwt.Parse([]byte(strToken), jwt.WithKeySet(*kSet), jwt.WithValidate(true))
		if err != nil {
			return false, errors.Wrap(err, "Error parsing token")
		}
	} else {

		// For each parent that might be here, get all owners and check that the token is signed by one of them
		owners := []string{}
		internalOwners := []string{}
		for _, parent := range lot.Parents {
			cOwners := unsafe.Pointer(nil)
			LotmanGetLotOwners(parent, true, &cOwners, &errMsg)
			if ret != 0 {
				trimBuf(&errMsg)
				return false, errors.Errorf("Error getting lot JSON: %s", string(errMsg))
			}
			internalOwners = append(internalOwners, cArrToGoArr(&cOwners)...)
		}

		// Handle possible duplicates
		occurred := map[string]bool{}
		for e := range internalOwners {
			if !occurred[internalOwners[e]] {
				occurred[internalOwners[e]] = true
				owners = append(owners, internalOwners[e])
			}
		}

		ownerFound := false
		for _, owner := range owners {
			kSet, err := utils.GetJWKSFromIssUrl(owner)

			// Print the kSet as a string for debugging
			kSetStr, _ := json.Marshal(kSet)
			log.Debugf("JWKS for owner %s: %s", owner, string(kSetStr))
			if err != nil {
				log.Debugf("Error getting JWKS for owner %s: %v", owner, err)
				continue
			}
			tok, err = jwt.Parse([]byte(strToken), jwt.WithKeySet(*kSet), jwt.WithValidate(true))
			if err != nil {
				log.Debugf("Token verification failed with owner %s: %v -- skipping", owner, err)
				continue
			}
			ownerFound = true
			break
		}

		if !ownerFound {
			return false, errors.New("token not signed by any of the owners of any parent lot")
		}
	}

	// We've determined the token is signed by someone we like, now to check that it has the correct lot.create permission!
	scope_any, present := tok.Get("scope")
	if !present {
		return false, errors.New("No scope claim in token")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}
	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if scope == token_scopes.Lot_Create.String() {
			tokenApproved = true
			break
		}
	}

	if !tokenApproved {
		return false, errors.New("The token was correctly signed but did not possess the necessary lot.create scope")
	}

	// At this point, we have a good token, now we need to get the appropriate owner for the lot.
	// To do this, we get a namespace from the path and then get the issuer for that namespace. If no
	// namespace exists, we'll assign ownership to the federation.

	// TODO: Once we have the new Director endpoint that returns a namespace for a given path, we'll use that
	// and cut out a lot of this cruft

	// Get the namespace by querying the director and checking the headers
	errMsgPrefix := "the provided token is acceptible, but no owner could be determined because "
	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if directorUrlStr == "" {
		return false, errors.New(errMsgPrefix + "the federation director URL is not set")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return false, errors.Wrap(err, errMsgPrefix+"the federation director URL is not a valid URL")
	}

	directorUrl.Path, err = url.JoinPath("/api/v1.0/director/object", path)
	if err != nil {
		return false, errors.Wrap(err, errMsgPrefix+"the director URL could not be joined with the path")
	}

	// Get the namespace by querying the director and checking the headers. The client should NOT
	// follow the redirect
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", directorUrl.String(), nil)
	if err != nil {
		return false, errors.Wrap(err, errMsgPrefix+"the director request could not be created")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, errors.Wrapf(err, errMsgPrefix+"the director couldn't be queried for path %s", path)
	}

	// Check the response code, make sure it's not in the error ranges (400-500)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, errors.Errorf(errMsgPrefix+"the director returned a bad status for path %s: %s", path, resp.Status)
	}

	// Get the namespace from the X-Pelican-Namespace header
	namespaceHeader := resp.Header.Values("X-Pelican-Namespace")
	xPelicanNamespaceMap := client.HeaderParser(namespaceHeader[0])
	namespace := xPelicanNamespaceMap["namespace"]

	// Get the issuer URL for that namespace
	nsIssuerUrl, err := utils.GetNSIssuerURL(namespace)
	if err != nil {
		return false, errors.Wrapf(err, errMsgPrefix+"no issuer could be found for namespace %s", namespace)
	}
	lot.Owner = nsIssuerUrl

	return true, nil
}

func VerifyDeleteLotToken(lotName string, strToken string) (bool, error) {
	// Get all parents of the lot, which we use to determine owners who can modify the lot itself (as opposed
	// to the data in the lot).
	tokenApproved := false

	log.Debugf("Attempting to delete lot %s", lotName)
	authzCallers, err := getAuthorizedCallers(lotName)
	if err != nil {
		return false, errors.Wrap(err, "Error getting authorized callers")
	}

	ownerSigned, tok, err := tokenSignedByAuthorizedCaller(strToken, authzCallers)
	if err != nil {
		return false, errors.Wrap(err, "Error verifying token is appropriately signed")
	}
	if !ownerSigned {
		return false, errors.New("Token not signed by any of the owners of any parent lot")
	}

	// We've determined the token is signed by someone we like, now to check that it has the correct lot.delete permission!
	scope_any, present := (*tok).Get("scope")
	if !present {
		return false, errors.New("no scope claim in token")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}
	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if scope == token_scopes.Lot_Delete.String() {
			tokenApproved = true
			break
		}
	}

	if !tokenApproved {
		return false, errors.New("The token was correctly signed but did not possess the necessary lot.create scope")
	}

	return true, nil
}

func VerifyUpdateLotToken(lot *LotUpdate, strToken string) (bool, error) {
	tokenApproved := false
	log.Debugf("Attempting to update lot %s", lot.LotName)

	// Since we're updating the lot, assume it already exists (lotman will yell if it doesn't).
	// Then we can make sure the token is signed by any owners of the lot's parents

	authzCallers, err := getAuthorizedCallers(lot.LotName)
	if err != nil {
		return false, errors.Wrap(err, "Error getting authorized callers")
	}

	// Now we have a list of owners who can modify the lot. We need to check that the token is signed by one of them
	ownerSigned, tok, err := tokenSignedByAuthorizedCaller(strToken, authzCallers)
	if err != nil {
		return false, errors.Wrap(err, "Error verifying token is appropriately signed")
	}
	if !ownerSigned {
		return false, errors.New("Token not signed by any of the owners of any parent lot")
	}

	// We've determined the token is signed by someone we like, now to check that it has the correct lot.modify permission!
	scope_any, present := (*tok).Get("scope")
	if !present {
		return false, errors.New("no scope claim in token")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}
	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if scope == token_scopes.Lot_Modify.String() {
			tokenApproved = true
			break
		}
	}

	if !tokenApproved {
		return false, errors.New("The token was correctly signed but did not possess the necessary lot.create scope")
	}

	return true, nil
}

// Initialize the LotMan library and bind its functions to the global vars
// We also perform a bit of extra setup such as setting the lotman db location
func InitLotman() bool {
	// If we've already tried to init the library, return the result of that attempt
	if lotmanInitTried {
		return lotmanInitSuccess
	}
	log.Infof("Initializing LotMan...")
	lotmanInitTried = true

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

	// Create the basic lots if they don't already exist. We'll make one for default
	// and one for the root namespace
	ret = LotmanLotExists("default", &errMsg)
	if ret < 0 {
		trimBuf(&errMsg)
		log.Errorf("Error checking if default lot exists: %s", string(errMsg))
		return false
	} else if ret == 0 {
		// Create the default lot
		fmt.Printf("\n\n\nCreating default lot\n\n\n")
		fmt.Printf("\n\n\nFEDERATION DISCOVERY URL: %s\n\n\n", param.Federation_DiscoveryUrl.GetString())
		// Under our model, we set owner to the issuer. Since this is owned by the federation, we set it in order of preference:
		// 1. The federation's discovery url
		// 2. The federation's director url
		// TODO: Consider what happens to the lot if either of these values change in the future after the lot is created?
		owner := param.Federation_DiscoveryUrl.GetString()
		if owner == "" {
			owner = param.Federation_DirectorUrl.GetString()
		}

		initDedicatedGB := float64(0)
		initOpportunisticGB := float64(0)
		defaultLot := Lot{
			LotName: "default",
			// Set the owner to the Federation's discovery url -- under this model, we can treat it like an issuer
			Owner: owner,
			// A self-parent lot indicates superuser status
			Parents: []string{"default"},
			MPA: &MPA{
				DedicatedGB:     &initDedicatedGB,
				OpportunisticGB: &initOpportunisticGB,
				MaxNumObjects:   &Int64FromFloat{Value: 0},
				CreationTime:    &Int64FromFloat{Value: 0},
				ExpirationTime:  &Int64FromFloat{Value: 0},
				DeletionTime:    &Int64FromFloat{Value: 0},
			},
		}

		fmt.Printf("\n DEFAULT LOT: %v\n\n\n", defaultLot)

		err := CreateLot(&defaultLot, "foobar")
		if err != nil {
			log.Errorf("Error creating default lot: %v", err)
			return false
		}

		log.Infof("Created default lot")
	}

	ret = LotmanLotExists("root", &errMsg)
	if ret < 0 {
		trimBuf(&errMsg)
		log.Errorf("Error checking if root lot exists: %s", string(errMsg))
		return false
	} else if ret == 0 {
		// Create the root lot
		owner := param.Federation_DiscoveryUrl.GetString()
		if owner == "" {
			owner = param.Federation_DirectorUrl.GetString()
		}

		initDedicatedGB := float64(0)
		initOpportunisticGB := float64(0)
		rootLot := Lot{
			LotName: "root",
			Owner:   owner,
			// A self-parent lot indicates superuser status
			Parents: []string{"root"},
			Paths: []LotPaths{
				{
					Path:      "/",
					Recursive: false,
				},
			},
			MPA: &MPA{
				DedicatedGB:     &initDedicatedGB,
				OpportunisticGB: &initOpportunisticGB,
				MaxNumObjects:   &Int64FromFloat{Value: 0},
				CreationTime:    &Int64FromFloat{Value: 0},
				ExpirationTime:  &Int64FromFloat{Value: 0},
				DeletionTime:    &Int64FromFloat{Value: 0},
			},
		}

		err := CreateLot(&rootLot, "foobar")
		if err != nil {
			log.Errorf("Error creating root lot: %v", err)
			return false
		}
	}

	log.Infof("LotMan initialization complete")
	lotmanInitSuccess = true
	return true
}

func CreateLot(newLot *Lot, caller string) error {
	// Marshal the JSON into a string for the C function
	lotJSON, err := json.Marshal(*newLot)
	if err != nil {
		return errors.Wrapf(err, "Error marshalling lot JSON: %v", err)
	}
	fmt.Printf("\n\n\nLot JSON: %s\n\n\n", string(lotJSON))

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

func GetLot(lotName string, recursive bool) (Lot, error) {
	// Haven't given much thought to these buff sizes yet
	outputBuf := make([]byte, 4096)
	errMsg := make([]byte, 2048)

	ret := LotmanGetLotJSON(lotName, recursive, &outputBuf, &errMsg)
	if ret != 0 {
		fmt.Printf("\n\n\n WE HIT AN ERROR: %s\n\n\n", string(errMsg))
		trimBuf(&errMsg)
		return Lot{}, errors.Errorf("Error getting lot JSON: %s", string(errMsg))
	}
	trimBuf(&outputBuf)
	fmt.Printf("\n\n\nRAW OUTPUT: %s\n\n\n", string(outputBuf))
	var lot Lot
	err := json.Unmarshal(outputBuf, &lot)
	if err != nil {
		return Lot{}, errors.Wrapf(err, "Error unmarshalling lot JSON: %v", err)
	}
	return lot, nil
}

func UpdateLot(lotUpdate *LotUpdate, caller string) error {
	// Marshal the JSON into a string for the C function
	updateJSON, err := json.Marshal(*lotUpdate)
	if err != nil {
		return errors.Wrapf(err, "Error marshalling lot JSON: %v", err)
	}
	fmt.Printf("\n\n\nLot JSON: %s\n\n\n", string(updateJSON))

	errMsg := make([]byte, 2048)
	callerMutex.Lock()
	defer callerMutex.Unlock()
	fmt.Printf("\n\n\nSetting caller to %s\n\n\n", caller)
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
