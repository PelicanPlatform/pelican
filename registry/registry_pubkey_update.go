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

package registry

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
)

type RegisteredPrefixUpdate struct {
	ClientNonce             string `json:"client_nonce"`
	ClientPayload           string `json:"client_payload"`
	ClientSignature         string `json:"client_signature"`
	KeyUpdateAuthzSignature string `json:"key_update_authz_signature"`
	MatchedKeyId            string `json:"matched_key_id"`

	ServerNonce     string `json:"server_nonce"`
	ServerPayload   string `json:"server_payload"`
	ServerSignature string `json:"server_signature"`

	Pubkey     json.RawMessage `json:"pubkey"`
	AllPubkeys json.RawMessage `json:"all_pubkeys"`
	Prefixes   []string        `json:"prefixes"`
}

// Generate server nonce for key-sign challenge when updating the public key of registered namespace(s)
func updateNsKeySignChallengeInit(data *RegisteredPrefixUpdate) (map[string]interface{}, error) {
	serverNonce, err := generateNonce()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate nonce for key-sign challenge")
	}

	serverPayload := []byte(data.ClientNonce + data.ServerNonce)

	privateKey, err := loadServerKeys()
	if err != nil {
		return nil, errors.Wrap(err, "Server is unable to generate a key sign challenge: Failed to load the server's private key")
	}

	serverSignature, err := signPayload(serverPayload, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to sign payload for key-sign challenge")
	}

	registeredKeysOnNs := make(map[string]string)
	for _, prefix := range data.Prefixes {
		existingNs, err := getNamespaceByPrefix(prefix)
		if err != nil {
			log.Errorf("Namespace %s not exists: %v", prefix, err)
			return nil, errors.Wrapf(err, "Server encountered an error retrieving namespace %s", prefix)
		}
		registeredKeysOnNs[prefix] = existingNs.Pubkey
	}
	res := map[string]interface{}{
		"server_nonce":     serverNonce,
		"client_nonce":     data.ClientNonce,
		"server_payload":   hex.EncodeToString(serverPayload),
		"server_signature": hex.EncodeToString(serverSignature),
		"registered_keys":  registeredKeysOnNs,
	}
	return res, nil
}

// Compare two jwk.Set objects to see if they are the same
//
// Similar in spirit to the internal function config.areKeysDifferent.
func compareJwks(jwks1, jwks2 jwk.Set) bool {
	if jwks1.Len() != jwks2.Len() {
		return false
	}
	ctx := context.Background()
	for jwksIter1 := jwks1.Keys(ctx); jwksIter1.Next(ctx); {
		found := false
		key1 := jwksIter1.Pair().Value.(jwk.Key)
		for jwksIter2 := jwks2.Keys(ctx); jwksIter2.Next(ctx); {
			key2 := jwksIter2.Pair().Value.(jwk.Key)
			if jwk.Equal(key1, key2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Update the public key of registered prefix(es) if the http request passed client and server verification for nonce.
// It returns the response data, and an error if any
func updateNsKeySignChallengeCommit(data *RegisteredPrefixUpdate) (map[string]interface{}, error) {
	// Validate the client's jwks as a set here
	key, err := validateJwks(string(data.Pubkey))
	if err != nil {
		return nil, badRequestError{Message: err.Error()}
	}
	var rawkey interface{} // This is the raw key, like *ecdsa.PrivateKey
	if err := key.Raw(&rawkey); err != nil {
		return nil, errors.Wrap(err, "failed to generate raw pubkey from jwks")
	}

	// Verify the Proof of Possession of the client and server's active private keys
	clientPayload := []byte(data.ClientNonce + data.ServerNonce)
	clientSignature, err := hex.DecodeString(data.ClientSignature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode the client's signature")
	}
	clientVerified := verifySignature(clientPayload, clientSignature, (rawkey).(*ecdsa.PublicKey))
	serverPayload, err := hex.DecodeString(data.ServerPayload)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode the server's payload")
	}

	serverSignature, err := hex.DecodeString(data.ServerSignature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode the server's signature")
	}

	serverPrivateKey, err := loadServerKeys()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode the server's private key")
	}
	serverPubkey := serverPrivateKey.PublicKey
	serverVerified := verifySignature(serverPayload, serverSignature, &serverPubkey)

	// Overwrite the namespace's public key(s) with the latest keys in the origin
	if clientVerified && serverVerified {
		for _, prefix := range data.Prefixes {
			log.Debug("Start updating namespace: ", prefix)

			// We ensure the prefix exists in registry db via updateNsKeySignChallengeInit function

			existingNs, err := getNamespaceByPrefix(prefix)
			if err != nil {
				log.Errorf("Failed to get existing namespace to update: %v", err)
				return nil, errors.Wrap(err, "Server encountered an error getting existing namespace to update")
			}

			// Verify the origin is authorized to update
			registryDbKeySet := jwk.NewSet()
			err = json.Unmarshal([]byte(existingNs.Pubkey), &registryDbKeySet)
			if err != nil {
				log.Errorf("Failed to parse public key as JWKS of registered namespace %s: %v", prefix, err)
				return nil, errors.Wrapf(err, "Invalid public key format of registered namespace %s", prefix)
			}

			// Get client's signature from payload
			keyUpdateAuthzSignature, err := hex.DecodeString(data.KeyUpdateAuthzSignature)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to decode the client's key update authorization signature")
			}

			// Look for the matched key sent back from the client in `registryDbKeySet`
			matchedKey, found := registryDbKeySet.LookupKeyID(data.MatchedKeyId)
			if !found {
				return nil, permissionDeniedError{
					Message: fmt.Sprintf("The client that tries to update prefix '%s' cannot be authorized because it doesn't contain any public key matching the existing namespace's public key in db", prefix),
				}
			}

			rawkey := &ecdsa.PublicKey{}
			if err := matchedKey.Raw(rawkey); err != nil {
				return nil, errors.Wrap(err, "failed to generate the raw key from the matched key")
			}

			keyUpdateAuthzVerified := verifySignature(clientPayload, keyUpdateAuthzSignature, rawkey)
			if !keyUpdateAuthzVerified {
				return nil, permissionDeniedError{
					Message: fmt.Sprintf("The client that tries to update prefix '%s' cannot be authorized because it fails to pass the proof of possession verification", prefix),
				}
			}

			// Process origin's latest public key(s)
			allPubkeyData, err := json.Marshal(data.AllPubkeys)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to convert the latest public key(s) from JSON to string format for the prefix %s", prefix)
			}
			clientJWKS, err := jwk.Parse(allPubkeyData)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to parse the client's public key(s) as JWKS")
			}

			// Perform the update action when the latest keys in the origin are different from the registered ones
			if compareJwks(clientJWKS, registryDbKeySet) {
				returnMsg := map[string]interface{}{
					"message": fmt.Sprintf("The public key of prefix %s hasn't changed -- nothing to update!", prefix),
				}
				log.Infof("The public key of prefix %s hasn't changed -- nothing to update!", prefix)
				return returnMsg, nil
			} else {
				err = setNamespacePubKey(prefix, string(data.AllPubkeys))
				log.Debugf("New public keys %s just replaced the old ones: %s", string(data.AllPubkeys), existingNs.Pubkey)
				if err != nil {
					log.Errorf("Failed to update the public key of namespace %s: %v", prefix, err)
					return nil, errors.Wrap(err, "Server encountered an error updating the public key of an existing namespace")
				}
				returnMsg := map[string]interface{}{
					"message": fmt.Sprintf("Updated the public key of namespace %s:", prefix),
				}
				log.Infof("Updated the public key of namespace %s:", prefix)
				return returnMsg, nil
			}

		}
	}

	return nil, errors.Errorf("Unable to verify the client's public key, or an encountered an error with its own: "+
		"server verified:%t, client verified:%t", serverVerified, clientVerified)

}

// Handle the registered namespace public key update with nonce generation and verification
func updateNsKeySignChallenge(data *RegisteredPrefixUpdate) (map[string]interface{}, error) {
	if data.ClientNonce != "" && data.ClientPayload != "" && data.ClientSignature != "" &&
		data.ServerNonce != "" && data.ServerPayload != "" && data.ServerSignature != "" {
		res, err := updateNsKeySignChallengeCommit(data)
		if err != nil {
			return nil, err
		} else {
			return res, nil
		}
	} else if data.ClientNonce != "" {
		res, err := updateNsKeySignChallengeInit(data)
		if err != nil {
			return nil, err
		} else {
			return res, nil
		}
	} else {
		return nil, badRequestError{Message: "Key sign challenge is missing parameters"}
	}
}

func updateNamespacesPubKey(ctx *gin.Context) {

	var reqData RegisteredPrefixUpdate
	if err := ctx.BindJSON(&reqData); err != nil {
		log.Errorln("Bad request: ", err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Bad Request: ", err.Error())})
		return
	}

	res, err := updateNsKeySignChallenge(&reqData)
	if err != nil {
		if errors.As(err, &permissionDeniedError{}) {
			ctx.JSON(http.StatusForbidden,
				server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    fmt.Sprintf("You don't have permission to update the registered public key of the prefix: %v", err),
				})
			return
		} else if errors.As(err, &badRequestError{}) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Bad request for key-sign challenge: %v", err),
			})
			return
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Server encountered an error during key-sign challenge: %v", err),
			})
			log.Warningf("Failed to complete key sign challenge without identity requirement: %v", err)
			return
		}
	} else {
		ctx.JSON(http.StatusOK, res)
		return
	}
}
