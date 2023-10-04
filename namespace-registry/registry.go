/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package nsregistry

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	// use this sqlite driver instead of the one from
	// github.com/mattn/go-sqlite3, because this one
	// doesn't require compilation with CGO_ENABLED
	_ "modernc.org/sqlite"
)

var OIDC struct {
	ClientID           string
	ClientSecret       string
	Scope              string
	DeviceAuthEndpoint string
	TokenEndpoint      string
	UserInfoEndpoint   string
	GrantType          string
}

var (
	// Loading of public/private keys for signing challenges
	serverCredsLoad    sync.Once
	serverCredsPrivKey *ecdsa.PrivateKey
	serverCredsErr     error
)

type Response struct {
	VerificationURLComplete string `json:"verification_uri_complete"`
	DeviceCode              string `json:"device_code"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

/*
Various auxiliary functions used for client-server security handshakes
*/
type registrationData struct {
	ClientNonce     string `json:"client_nonce"`
	ClientPayload   string `json:"client_payload"`
	ClientSignature string `json:"client_signature"`

	ServerNonce     string `json:"server_nonce"`
	ServerPayload   string `json:"server_payload"`
	ServerSignature string `json:"server_signature"`

	Pubkey           json.RawMessage `json:"pubkey"`
	AccessToken      string          `json:"access_token"`
	Identity         string          `json:"identity"`
	IdentityRequired string          `json:"identity_required"`
	DeviceCode       string          `json:"device_code"`
	Prefix           string          `json:"prefix"`
}

func keySignChallenge(ctx *gin.Context, data *registrationData, action string) error {
	if data.ClientNonce != "" && data.ClientPayload != "" && data.ClientSignature != "" &&
		data.ServerNonce != "" && data.ServerPayload != "" && data.ServerSignature != "" {
		err := keySignChallengeCommit(ctx, data, action)
		if err != nil {
			return errors.Wrap(err, "commit failed")
		}
	} else if data.ClientNonce != "" {
		err := keySignChallengeInit(ctx, data)
		if err != nil {
			return errors.Wrap(err, "init failed")
		}

	} else {
		ctx.JSON(http.StatusMultipleChoices, gin.H{"error": "MISSING PARAMETERS"})
		return errors.New("key sign challenge was missing parameters")
	}
	return nil
}

func generateNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

func loadServerKeys() (*ecdsa.PrivateKey, error) {
	// Note: go 1.21 introduces `OnceValues` which automates this procedure.
	// TODO: Reimplement the function once we switch to a minimum of 1.21
	serverCredsLoad.Do(func() {
		issuerFileName := param.IssuerKey.GetString()
		serverCredsPrivKey, serverCredsErr = config.LoadPrivateKey(issuerFileName)
	})
	return serverCredsPrivKey, serverCredsErr
}

func loadOIDC() error {
	// Load OIDC.ClientID
	OIDCClientIDFile := param.OIDC_ClientIDFile.GetString()
	OIDCClientIDFromEnv := viper.GetString("OIDCCLIENTID")
	if OIDCClientIDFile != "" {
		contents, err := os.ReadFile(OIDCClientIDFile)
		if err != nil {
			return errors.Wrapf(err, "Failed reading provided OIDC.ClientIDFile %s", OIDCClientIDFile)
		}
		OIDC.ClientID = strings.TrimSpace(string(contents))
	} else if OIDCClientIDFromEnv != "" {
		OIDC.ClientID = OIDCClientIDFromEnv
	} else {
		return errors.New("An OIDC Client Identity file must be specified in the config (OIDC.ClientIDFile)," +
			" or the identity must be provided via the environment variable PELICAN_OIDCCLIENTID")
	}

	// load OIDC.ClientSecret
	OIDCClientSecretFile := param.OIDC_ClientSecretFile.GetString()
	OIDCClientSecretFromEnv := viper.GetString("OIDCCLIENTSECRET")
	if OIDCClientSecretFile != "" {
		contents, err := os.ReadFile(OIDCClientSecretFile)
		if err != nil {
			return errors.Wrapf(err, "Failed reading provided OIDCClientSecretFile %s", OIDCClientSecretFile)
		}
		OIDC.ClientSecret = strings.TrimSpace(string(contents))
	} else if OIDCClientSecretFromEnv != "" {
		OIDC.ClientSecret = OIDCClientSecretFromEnv
	} else {
		return errors.New("An OIDC Client Secret file must be specified in the config (OIDC.ClientSecretFile)," +
			" or the secret must be provided via the environment variable PELICAN_OIDCCLIENTSECRET")
	}

	// Load OIDC.DeviceAuthEndpoint
	deviceAuthEndpoint := param.OIDC_DeviceAuthEndpoint.GetString()
	if deviceAuthEndpoint == "" {
		return errors.New("Nothing set for config parameter OIDC.DeviceAuthEndpoint, so registration with identity not supported")
	}
	deviceAuthEndpointURL, err := url.Parse(deviceAuthEndpoint)
	if err != nil {
		return errors.New("Failed to parse URL for parameter OIDC.DeviceAuthEndpoint")
	}
	OIDC.DeviceAuthEndpoint = deviceAuthEndpointURL.String()

	// Load OIDC.TokenEndpoint
	tokenEndpoint := param.OIDC_TokenEndpoint.GetString()
	if tokenEndpoint == "" {
		return errors.New("Nothing set for config parameter OIDC.TokenEndpoint, so registration with identity not supported")
	}
	tokenAuthEndpointURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		return errors.New("Failed to parse URL for parameter OIDC.TokenEndpoint")
	}
	OIDC.TokenEndpoint = tokenAuthEndpointURL.String()

	// Load OIDC.UserInfoEndpoint
	userInfoEndpoint := param.OIDC_TokenEndpoint.GetString()
	if userInfoEndpoint == "" {
		return errors.New("Nothing set for config parameter OIDC.UserInfoEndpoint, so registration with identity not supported")
	}
	userInfoEndpointURL, err := url.Parse(userInfoEndpoint)
	if err != nil {
		return errors.New("Failed to parse URL for parameter OIDC.UserInfoEndpoint")
	}
	OIDC.UserInfoEndpoint = userInfoEndpointURL.String()

	// Set the scope
	OIDC.Scope = "openid profile email org.cilogon.userinfo"

	// Set the grant type
	OIDC.GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	return nil
}

func signPayload(payload []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(payload)
	signature, err := privateKey.Sign(rand.Reader, hash[:], crypto.SHA256) // Use crypto.SHA256 instead of the hash[:]
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func verifySignature(payload []byte, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

func keySignChallengeInit(ctx *gin.Context, data *registrationData) error {
	serverNonce, err := generateNonce()
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to generate nonce for key sign challenge"})
		return errors.Wrap(err, "Failed to generate nonce for key-sign challenge")
	}

	serverPayload := []byte(data.ClientNonce + data.ServerNonce)

	privateKey, err := loadServerKeys()
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Server is unable to generate a key sign challenge"})
		return errors.Wrap(err, "Failed to load the server's private key")
	}

	serverSignature, err := signPayload(serverPayload, privateKey)
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failure when signing the challenge"})
		return errors.Wrap(err, "Failed to sign payload for key-sign challenge")
	}

	ctx.JSON(http.StatusOK, gin.H{
		"server_nonce":     serverNonce,
		"client_nonce":     data.ClientNonce,
		"server_payload":   hex.EncodeToString(serverPayload),
		"server_signature": hex.EncodeToString(serverSignature),
	})
	return nil
}

func keySignChallengeCommit(ctx *gin.Context, data *registrationData, action string) error {
	// Parse the client's jwks as a set here
	clientJwks, err := jwk.Parse(data.Pubkey)
	if err != nil {
		return errors.Wrap(err, "Couldn't parse the pubkey from the client")
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		// Let's check that we can convert to JSON and get the right thing...
		jsonbuf, err := json.Marshal(clientJwks)
		if err != nil {
			return errors.Wrap(err, "failed to marshal the client's keyset into JSON")
		}
		log.Debugln("Client JWKS as seen by the registry server:", string(jsonbuf))
	}

	/*
	 * TODO: This section makes the assumption that the incoming jwks only contains a single
	 *       key, a property that is enforced by the client at the origin. Eventually we need
	 *       to support the addition of other keys in the jwks stored for the origin. There is
	 *       a similar TODO listed in client_commands.go, as the choices made there mirror the
	 *       choices made here.
	 */
	key, exists := clientJwks.Key(0)
	if !exists {
		return errors.New("There was no key at index 0 in the client's JWKS. Something is wrong")
	}

	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err := key.Raw(&rawkey); err != nil {
		return errors.Wrap(err, "failed to generate raw pubkey from jwks")
	}

	clientPayload := []byte(data.ClientNonce + data.ServerNonce)
	clientSignature, err := hex.DecodeString(data.ClientSignature)
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to decode client's signature"})
		return errors.Wrap(err, "Failed to decode the client's signature")
	}
	clientVerified := verifySignature(clientPayload, clientSignature, (rawkey).(*ecdsa.PublicKey))
	serverPayload, err := hex.DecodeString(data.ServerPayload)
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to decode the server's payload"})
		return errors.Wrap(err, "Failed to decode the server's payload")
	}

	serverSignature, err := hex.DecodeString(data.ServerSignature)
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to decode the server's signature"})
		return errors.Wrap(err, "Failed to decode the server's signature")
	}

	serverPrivateKey, err := loadServerKeys()
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to load server's private key"})
		return errors.Wrap(err, "Failed to decode the server's private key")
	}
	serverPubkey := serverPrivateKey.PublicKey
	serverVerified := verifySignature(serverPayload, serverSignature, &serverPubkey)

	if clientVerified && serverVerified {
		if action == "register" {
			log.Debug("Registering namespace ", data.Prefix)

			// Check if prefix exists before doing anything else
			exists, err := namespaceExists(data.Prefix)
			if err != nil {
				log.Errorf("Failed to check if namespace already exists: %v", err)
				return errors.Wrap(err, "Server encountered an error checking if namespace already exists")
			}
			if exists {
				return errors.New("The prefix already is registered")
			}
			reqPrefix, err := validateNSPath(data.Prefix)
			if err != nil {
				err = errors.Wrapf(err, "Requested namespace %s failed validation", reqPrefix)
				log.Errorln(err)
				return err
			}
			data.Prefix = reqPrefix

			// Verify the requested path is a valid prefix
			if err != nil {
				ctx.JSON(http.StatusForbidden, gin.H{"error": "Namespace prefix cannot be registered as it is invalid"})
				return errors.Wrapf(err, "Namespace prefix %s cannot be registered as it is invalid", data.Prefix)
			}

			err = dbAddNamespace(ctx, data)
			if err != nil {
				ctx.JSON(500, gin.H{"error": "The server encountered an error while attempting to add the prefix to its database"})
				return errors.Wrapf(err, "Failed while trying to add to database")
			}
			return nil
		}
	} else {
		ctx.JSON(500, gin.H{"error": "Server was either unable to verify the client's public key, or an encountered an error with its own"})
		return errors.Errorf("Either the server or the client could not be verified: "+
			"server verified:%t, client verified:%t", serverVerified, clientVerified)
	}
	return nil
}

func validateNSPath(nspath string) (string, error) {
	if len(nspath) == 0 {
		return "", errors.New("Path prefix may not be empty")
	}
	if nspath[0] != '/' {
		return "", errors.New("Path prefix must be absolute - relative paths are not allowed")
	}
	components := strings.Split(nspath, "/")[1:]
	if len(components) == 0 {
		return "", errors.New("Cannot register the prefix '/' for an origin")
	} else if components[0] == "api" {
		return "", errors.New("Cannot register a prefix starting with '/api'")
	} else if components[0] == "view" {
		return "", errors.New("Cannot register a prefix starting with '/view'")
	} else if components[0] == "pelican" {
		return "", errors.New("Cannot register a prefix starting with '/pelican'")
	}
	result := ""
	for _, component := range components {
		if len(component) == 0 {
			continue
		} else if component == "." {
			return "", errors.New("Path component cannot be '.'")
		} else if component == ".." {
			return "", errors.New("Path component cannot be '..'")
		} else if component[0] == '.' {
			return "", errors.New("Path component cannot begin with a '.'")
		}
		result += "/" + component
	}
	if result == "/" || len(result) == 0 {
		return "", errors.New("Cannot register the prefix '/' for an origin")
	}
	return result, nil
}

/*
Handler functions called upon by the gin router
*/
func cliRegisterNamespace(ctx *gin.Context) {
	var reqData registrationData
	if err := ctx.BindJSON(&reqData); err != nil {
		log.Errorln("Bad request: ", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}

	if reqData.AccessToken != "" {
		payload := url.Values{}
		payload.Set("access_token", reqData.AccessToken)

		err := loadOIDC()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server has malformed OIDC configuration"})
			log.Errorf("Failed to load OIDC information for registration with identity: %v", err)
			return
		}

		resp, err := http.PostForm(OIDC.UserInfoEndpoint, payload)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error making request to user info endpoint"})
			log.Errorf("Failed to execute post form to user info endpoint %s: %v", OIDC.UserInfoEndpoint, err)
			return
		}
		defer resp.Body.Close()

		// Check the status code
		if resp.StatusCode != 200 {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server received non-200 status from user info endpoint"})
			log.Errorf("The user info endpoint %s responded with status code %d", OIDC.UserInfoEndpoint, resp.StatusCode)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Server encountered an error reading response from user info endpoint"})
			log.Errorf("Failed to read body from user info endpoint %s: %v", OIDC.UserInfoEndpoint, err)
			return
		}

		reqData.Identity = string(body)
		err = keySignChallenge(ctx, &reqData, "register")
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error during key-sign challenge"})
			log.Errorf("Failed to complete key sign challenge with identity requirement: %v", err)
		}
		return
	}

	if reqData.IdentityRequired == "false" || reqData.IdentityRequired == "" {
		err := keySignChallenge(ctx, &reqData, "register")
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error during key-sign challenge"})
			log.Errorf("Failed to complete key sign challenge without identity requirement: %v", err)
		}
		return
	}

	err := loadOIDC()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server has malformed OIDC configuration"})
		log.Errorf("Failed to load OIDC information for registration with identity: %v", err)
		return
	}

	if reqData.DeviceCode == "" {
		log.Debug("Getting Device Code")
		payload := url.Values{}
		payload.Set("client_id", OIDC.ClientID)
		payload.Set("client_secret", OIDC.ClientSecret)
		payload.Set("scope", OIDC.Scope)

		response, err := http.PostForm(OIDC.DeviceAuthEndpoint, payload)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered error requesting device code"})
			log.Errorf("Failed to execute post form to device auth endpoint %s: %v", OIDC.DeviceAuthEndpoint, err)
			return
		}
		defer response.Body.Close()

		// Check the response code
		if response.StatusCode != 200 {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server received non-200 status code from OIDC device auth endpoint"})
			log.Errorf("The device auth endpoint %s responded with status code %d", OIDC.DeviceAuthEndpoint, response.StatusCode)
			return
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered error reading response from device auth endpoint"})
			log.Errorf("Failed to read body from device auth endpoint %s: %v", OIDC.DeviceAuthEndpoint, err)
			return
		}
		var res Response
		err = json.Unmarshal(body, &res)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server could not parse response from device auth endpoint"})
			log.Errorf("Failed to unmarshal body from device auth endpoint %s: %v", OIDC.DeviceAuthEndpoint, err)
			return
		}
		verificationURL := res.VerificationURLComplete
		deviceCode := res.DeviceCode
		ctx.JSON(http.StatusOK, gin.H{
			"device_code":      deviceCode,
			"verification_url": verificationURL,
		})
		return
	} else {
		log.Debug("Verifying Device Code")
		payload := url.Values{}
		payload.Set("client_id", OIDC.ClientID)
		payload.Set("client_secret", OIDC.ClientSecret)
		payload.Set("device_code", reqData.DeviceCode)
		payload.Set("grant_type", OIDC.GrantType)

		response, err := http.PostForm(OIDC.TokenEndpoint, payload)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error while making request to token endpoint"})
			log.Errorf("Failed to execute post form to token endpoint %s: %v", OIDC.TokenEndpoint, err)
			return
		}
		defer response.Body.Close()

		// Check the status code
		// We accept either a 200, or a 400.
		if response.StatusCode != 200 && response.StatusCode != 400 {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server received bad status code from token endpoint"})
			log.Errorf("The token endpoint %s responded with status code %d", OIDC.TokenEndpoint, response.StatusCode)
			return
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error reading response from token endpoint"})
			log.Errorf("Failed to read body from token endpoint %s: %v", OIDC.TokenEndpoint, err)
			return
		}

		var tokenResponse TokenResponse
		err = json.Unmarshal(body, &tokenResponse)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server could not parse error from token endpoint"})
			log.Errorf("Failed to unmarshal body from token endpoint %s: %v", OIDC.TokenEndpoint, err)
			return
		}

		// Now we check the status code for a specific case. If it was 400, we check the error in the body
		// to make sure it's "authorization_pending"
		if tokenResponse.AccessToken == "" {
			if response.StatusCode == 400 && tokenResponse.Error == "authorization_pending" {
				ctx.JSON(http.StatusOK, gin.H{
					"status": "PENDING",
				})
			} else {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered unknown error waiting for token"})
				log.Errorf("Token endpoint did not provide a token, and responded with unkown error: %s", string(body))
				return
			}
		} else {
			ctx.JSON(http.StatusOK, gin.H{
				"status":       "APPROVED",
				"access_token": tokenResponse.AccessToken,
			})
		}
		return
	}
}

func dbAddNamespace(ctx *gin.Context, data *registrationData) error {
	var ns Namespace
	ns.Prefix = data.Prefix

	pubkeyData, err := json.Marshal(data.Pubkey)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal the pubkey for prefix %s", ns.Prefix)
	}
	ns.Pubkey = string(pubkeyData)
	if data.Identity != "" {
		ns.Identity = data.Identity
	}

	err = addNamespace(&ns)
	if err != nil {
		return errors.Wrapf(err, "Failed to add prefix %s", ns.Prefix)
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "success"})
	return nil
}

func dbDeleteNamespace(ctx *gin.Context) {
	/*
		A weird feature of gin is that wildcards always
		add a preceding /. Since the URL parsing that happens
		upstream removes the prefixed / that gets sent, we
		can just leave the one that's added back by the wildcard
		because that reflects the path that's getting stored.
	*/
	prefix := ctx.Param("wildcard")
	log.Debug("Attempting to delete namespace prefix ", prefix)

	// Check if prefix exists before trying to delete it
	exists, err := namespaceExists(prefix)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error checking if namespace already exists"})
		log.Errorf("Failed to check if the namespace already exists: %v", err)
		return
	}
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "the prefix does not exist so it cannot be deleted"})
		log.Errorln("prefix could not be deleted because it does not exist")
	}

	/*
	*  Need to check that we were provided a token and that it's valid for the origin
	*  TODO: Should we also investigate checking for the token in the url, in case we
	*		 need that option at a later point?
	 */
	authHeader := ctx.GetHeader("Authorization")
	delTokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Have the token, now we need to load the JWKS for the prefix
	originJwks, err := dbGetPrefixJwks(prefix)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error loading the prefix's stored jwks"})
		log.Errorf("Failed to get prefix's stored jwks: %v", err)
		return
	}

	// Use the JWKS to verify the token -- verification means signature integrity
	parsed, err := jwt.Parse([]byte(delTokenStr), jwt.WithKeySet(*originJwks))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server could not verify/parse the provided deletion token"})
		log.Errorf("Failed to parse the token: %v", err)
		return
	}

	/*
	* The signature is verified, now we need to make sure this token actually gives us
	* permission to delete the namespace from the db. Let's check the subject and the scope.
	* NOTE: The validate function also handles checking `iat` and `exp` to make sure the token
	*       remains valid.
	 */
	scopeValidator := jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		scope_any, present := tok.Get("scope")
		if !present {
			return jwt.NewValidationError(errors.New("No scope is present; required for authorization"))
		}
		scope, ok := scope_any.(string)
		if !ok {
			return jwt.NewValidationError(errors.New("scope claim in token is not string-valued"))
		}

		for _, scope := range strings.Split(scope, " ") {
			if scope == "pelican.namespace_delete" {
				return nil
			}
		}
		return jwt.NewValidationError(errors.New("Token does not contain namespace deletion authorization"))
	})
	if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server could not validate the provided deletion token"})
		log.Errorf("Failed to validate the token: %v", err)
		return
	}

	// If we get to this point in the code, we've passed all the security checks and we're ready to delete
	err = deleteNamespace(prefix)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error deleting namespace from database"})
		log.Errorf("Failed to delete namespace from database: %v", err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "success"})
}

/**
 * Commenting out until we're ready to use it.  -BB
func cliListNamespaces(c *gin.Context) {
	prefix := c.Param("prefix")
	log.Debugf("Trying to get namespace data for prefix %s", prefix)
	ns, err := getNamespace(prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ns)
}
*/

func dbGetAllNamespaces(ctx *gin.Context) {
	nss, err := getAllNamespaces()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error trying to list all namespaces"})
		log.Errorln("Failed to get all namespaces: ", err)
		return
	}
	ctx.JSON(http.StatusOK, nss)
}

func metadataHandler(ctx *gin.Context) {
	// A weird feature of gin is that wildcards always
	// add a preceding /. Since the prefix / was trimmed
	// out during the url parsing, we can just leave the
	// new / here!
	path := ctx.Param("wildcard")

	// Get the prefix's JWKS
	if filepath.Base(path) == "issuer.jwks" {
		// do something
		prefix := strings.TrimSuffix(path, "/.well-known/issuer.jwks")
		jwks, err := dbGetPrefixJwks(prefix)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server encountered an error trying to get jwks for prefix"})
			log.Errorf("Failed to load jwks for prefix %s: %v", prefix, err)
			return
		}
		ctx.JSON(http.StatusOK, jwks)
	}

	// // Get OpenID config info
	// match, err := filepath.Match("*/\\.well-known/openid-configuration", path)
	// if err != nil {
	// 	log.Errorf("Failed to check incoming path for match: %v", err)
	// 	return
	// }
	// if match {
	// 	// do something
	// } else {
	// 	log.Errorln("Unknown request")
	// 	return
	// }

}

// func getJwks(prefix string) (*jwk.Set, error) {
// 	jwks, err := dbGetPrefixJwks(prefix)
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "Could not load jwks for prefix %s", prefix)
// 	}
// 	return jwks, nil
// }

/*
 Commenting out until we're ready to use it.  -BB
func getOpenIDConfiguration(c *gin.Context) {
	prefix := c.Param("prefix")
	c.JSON(http.StatusOK, gin.H{"status": "getOpenIDConfiguration is not implemented", "prefix": prefix})
}
*/

func RegisterNamespaceRegistry(router *gin.RouterGroup) {
	registry := router.Group("/api/v1.0/registry")
	{
		registry.POST("", cliRegisterNamespace)
		registry.GET("", dbGetAllNamespaces)
		// Will handle getting jwks, openid config, and listing namespaces
		registry.GET("/*wildcard", metadataHandler)

		registry.DELETE("/*wildcard", dbDeleteNamespace)
	}
}
