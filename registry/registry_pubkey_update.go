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
	ClientNonce         string `json:"client_nonce"`
	ClientPayload       string `json:"client_payload"`
	ClientSignature     string `json:"client_signature"`
	ClientPrevSignature string `json:"client_prev_signature"`

	ServerNonce     string `json:"server_nonce"`
	ServerPayload   string `json:"server_payload"`
	ServerSignature string `json:"server_signature"`

	Pubkey     json.RawMessage `json:"pubkey"`
	PrevPubkey json.RawMessage `json:"prev_pubkey"`
	AllPubkeys json.RawMessage `json:"all_pubkeys"`
	Prefixes   []string        `json:"prefixes"`
}

func getKeyByKid(keySet jwk.Set, kidToFind string) (jwk.Key, error) {
	for i := 0; i < keySet.Len(); i++ {
		key, _ := keySet.Key(i)
		kid, ok := key.Get("kid")
		if ok && kid == kidToFind {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key with kid %s not found in the set", kidToFind)
}

func constructUpdatedKeySet(keySet jwk.Set, kidToRemove string, keyToAdd jwk.Key) error {
	keyToRemove, err := getKeyByKid(keySet, kidToRemove)
	if err != nil {
		log.Warnf("Key %s not found in the key set, skipping removal: %v", kidToRemove, err)
	} else {
		// Remove the key only if it exists
		if err := keySet.RemoveKey(keyToRemove); err != nil {
			return errors.Wrap(err, "failed to remove key from set")
		}
	}
	if err := keySet.AddKey(keyToAdd); err != nil {
		return errors.Wrap(err, "failed to add key to the key set")
	}
	return nil
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

	res := map[string]interface{}{
		"server_nonce":     serverNonce,
		"client_nonce":     data.ClientNonce,
		"server_payload":   hex.EncodeToString(serverPayload),
		"server_signature": hex.EncodeToString(serverSignature),
	}
	return res, nil
}

// Update the public key of registered prefix(es) if the http request passed client and server verification for nonce.
// It returns the response data, and an error if any
func updateNsKeySignChallengeCommit(ctx *gin.Context, data *RegisteredPrefixUpdate) (map[string]interface{}, error) {
	// Validate the client's jwks as a set here
	key, err := validateJwks(string(data.Pubkey))
	if err != nil {
		return nil, badRequestError{Message: err.Error()}
	}
	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
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

	if clientVerified && serverVerified {
		for _, prefix := range data.Prefixes {
			log.Debug("Start updating namespace: ", prefix)

			// Check if prefix exists before doing anything else
			exists, err := namespaceExistsByPrefix(prefix)
			if err != nil {
				log.Errorf("Failed to check if namespace already exists: %v", err)
				return nil, errors.Wrap(err, "Server encountered an error checking if namespace already exists")
			}
			if exists {
				// Update the namespace's public key with the latest one when authorized origin provides a new key
				existingNs, err := getNamespaceByPrefix(prefix)
				if err != nil {
					log.Errorf("Failed to get existing namespace to update: %v", err)
					return nil, errors.Wrap(err, "Server encountered an error getting existing namespace to update")
				}

				// Check the origin is authorized to update (possessing the public key used for prefix initial registration)
				// Parse all public keys of the sender into a JWKS
				var clientKeySet jwk.Set
				if data.AllPubkeys == nil { // backward compatibility - AllPubkeys only exists in the payload in Pelican 7.12 or later
					clientKeySet, err = jwk.Parse(data.Pubkey)
				} else {
					clientKeySet, err = jwk.Parse(data.AllPubkeys)
				}
				if err != nil {
					log.Errorf("Failed to parse in-memory public keys of the client: %v", err)
					return nil, errors.Wrapf(err, "Invalid in-memory public keys format of the client")
				}
				// Parse `existingNs.Pubkey` as a JWKS
				registryDbKeySet := jwk.NewSet()
				err = json.Unmarshal([]byte(existingNs.Pubkey), &registryDbKeySet)
				if err != nil {
					log.Errorf("Failed to parse existing namespace public key as JWKS: %v", err)
					return nil, errors.Wrap(err, "Invalid existing namespace public key format")
				}

				// Get client's previous signature from payload
				prevKeyVerified := false
				if data.ClientPrevSignature == "" {
					prevKeyVerified = true
				}
				clientPrevSignature, err := hex.DecodeString(data.ClientPrevSignature)
				if err != nil {
					return nil, errors.Wrap(err, "Failed to decode the client's previous signature")
				}

				// Check if any key in `clientKeySet` matches a key in `registryDbKeySet`
				registryDbKeysIter := registryDbKeySet.Keys(ctx)
				clientKeysIter := clientKeySet.Keys(ctx)
				matchFound := false

				for registryDbKeysIter.Next(ctx) {
					registryDbKey := registryDbKeysIter.Pair().Value.(jwk.Key)

					registryDbKid, ok := registryDbKey.Get("kid")
					if !ok {
						log.Warnf("Skipping registry db existing key without 'kid'")
						continue
					}

					for clientKeysIter.Next(ctx) {
						clientKey := clientKeysIter.Pair().Value.(jwk.Key)

						clientKid, ok := clientKey.Get("kid")
						if !ok {
							log.Warnf("Skipping client key without 'kid'")
							continue
						}

						if registryDbKid == clientKid {
							// Verify the Proof of Possession of client's previous active private key
							// Get client's previous public key recorded in db
							var prevRawkey interface{}
							if err := registryDbKey.Raw(&prevRawkey); err != nil {
								return nil, errors.Wrap(err, "failed to generate raw pubkey from client's previous pubkey")
							}

							if data.ClientPrevSignature != "" {
								prevKeyVerified = verifySignature(clientPayload, clientPrevSignature, (prevRawkey).(*ecdsa.PublicKey))
							}

							if prevKeyVerified {
								matchFound = true
								break
							} else {
								log.Debugf("This key is not client's previous active key that it wants to rotate out, or client lacks proof of possession of claimed previous active key (kid: %s)", registryDbKid)
							}
						}
					}

					if matchFound {
						break
					}
				}

				if !matchFound {
					return nil, permissionDeniedError{
						Message: fmt.Sprintf("The client that tries to prefix '%s' cannot be authorized: either it doesn't contain any public key matching the existing namespace's public key in db, or it fails to pass the proof of possession verification", prefix),
					}
				}

				log.Debugf("New public key %s is going to replace the old one: %s", string(data.Pubkey), existingNs.Pubkey)

				// Process origin's new public key
				pubkeyData, err := json.Marshal(data.Pubkey)
				if err != nil {
					return nil, errors.Wrapf(err, "Failed to convert public key from json to string format for the prefix %s", prefix)
				}
				clientPubkeyString := string(pubkeyData)

				// Construct the updated JWKS to be stored in registry db
				prevKey, _ := validateJwks(string(data.PrevPubkey))
				err = constructUpdatedKeySet(registryDbKeySet, prevKey.KeyID(), key)
				if err != nil {
					return nil, errors.Wrap(err, "failed to construct the updated JWKS to be stored in registry db")
				}
				registryDbKeySetJson, err := json.Marshal(registryDbKeySet)
				if err != nil {
					return nil, errors.Wrap(err, "failed to marshal registryDbKeySet to JSON")
				}

				// Perform the update action when origin provides a new key
				if clientPubkeyString != existingNs.Pubkey {
					err = setNamespacePubKey(prefix, string(registryDbKeySetJson))
					if err != nil {
						log.Errorf("Failed to update the public key of namespace %s: %v", prefix, err)
						return nil, errors.Wrap(err, "Server encountered an error updating the public key of an existing namespace")
					}
					returnMsg := map[string]interface{}{
						"message": fmt.Sprintf("Updated the public key of namespace %s:", prefix),
					}
					log.Infof("Updated the public key of namespace %s:", prefix)
					return returnMsg, nil
				} else {
					returnMsg := map[string]interface{}{
						"message": fmt.Sprintf("The public key of prefix %s hasn't changed -- nothing to update!", prefix),
					}
					log.Infof("The public key of prefix %s hasn't changed -- nothing to update!", prefix)
					return returnMsg, nil
				}
			} else {
				log.Errorf("Prefix %s is not registered", prefix)
				return nil, errors.Errorf("Prefix %s is not registered", prefix)
			}
		}
	}

	return nil, errors.Errorf("Unable to verify the client's public key, or an encountered an error with its own: "+
		"server verified:%t, client verified:%t", serverVerified, clientVerified)

}

// Handle the registered namespace public key update with nonce generation and verifcation, regardless of
// using OIDC Authorization or not
func updateNsKeySignChallenge(ctx *gin.Context, data *RegisteredPrefixUpdate) (map[string]interface{}, error) {
	if data.ClientNonce != "" && data.ClientPayload != "" && data.ClientSignature != "" &&
		data.ServerNonce != "" && data.ServerPayload != "" && data.ServerSignature != "" {
		res, err := updateNsKeySignChallengeCommit(ctx, data)
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

	res, err := updateNsKeySignChallenge(ctx, &reqData)
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
