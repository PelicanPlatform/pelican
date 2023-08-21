package nsregistry

import (
	"github.com/gin-gonic/gin"
	// "github.com/joho/godotenv"
	"net/http"
	"crypto/rand"
	"encoding/hex"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"math/big"
	"crypto/elliptic"
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"os"
	"strings"
	"sync"
	log "github.com/sirupsen/logrus"
	
	// use this sqlite driver instead of the one from
	// github.com/mattn/go-sqlite3, because this one
	// doesn't require compilation with CGO_ENABLED
	_ "modernc.org/sqlite"
)

var (
	OIDCClientID       string
	OIDCClientSecret   string
	OIDCScope          string = "openid profile email org.cilogon.userinfo"
	DeviceAuthEndpoint string = "https://cilogon.org/oauth2/device_authorization"
	TokenEndpoint      string = "https://cilogon.org/oauth2/token"
	GrantType          string = "urn:ietf:params:oauth:grant-type:device_code"

	// Loading of public/private keys for signing challenges
	serverCredsLoad        sync.Once
	serverCredsPrivKey    *ecdsa.PrivateKey
	serverCredsErr         error
)

type Response struct {
	VerificationURLComplete string `json:"verification_uri_complete"`
	DeviceCode              string `json:"device_code"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

/*
Various auxiliary functions used for client-server security handshakes
*/
func keySignChallenge(c *gin.Context, data map[string]interface{}, action string) {
	_, cnOk := data["client_nonce"].(string)
	_, cpdOk := data["client_payload"].(string)
	_, csOk := data["client_signature"].(string)

	_, snOk := data["server_nonce"].(string)
	_, spOk := data["server_payload"].(string)
	_, ssOk := data["server_signature"].(string)

	_, cpOk := data["pubkey"].(map[string]interface{})

	if cnOk && snOk && cpOk && cpdOk && csOk && spOk && ssOk {
		keySignChallengeCommit(c, data, action)
	} else if cnOk {
		keySignChallengeInit(c, data)
	} else {
		log.Warningln("key sign challenge was missing parameters")
		c.JSON(http.StatusMultipleChoices, gin.H{"status": "MISSING PARAMETERS"})
	}
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
		issuerFileName := viper.GetString("IssuerKey")
		serverCredsPrivKey, serverCredsErr = config.LoadPrivateKey(issuerFileName)
	})
	return serverCredsPrivKey, serverCredsErr
}

func signPayload(payload []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
    hash := sha256.Sum256(payload)
    signature, err := privateKey.Sign(rand.Reader, hash[:], crypto.SHA256)  // Use crypto.SHA256 instead of the hash[:]
    if err != nil {
        return nil, err
    }
    return signature, nil
}

func verifySignature(payload []byte, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(publicKey, hash[:], signature)
}

func keySignChallengeInit(ctx *gin.Context, data map[string]interface{}) {
    clientNonce, _ := data["client_nonce"].(string)
	serverNonce, err := generateNonce()
	if err != nil {
		log.Errorln("Error generating nonce")
		ctx.JSON(500, gin.H{"error": "Failed to generate nonce for key sign challenge"})
		return
	}

    serverPayload := []byte(clientNonce + serverNonce)

	privateKey, err := loadServerKeys()
	if err != nil {
		log.Warningln("Failure to load the server's private key:", err)
		ctx.JSON(500, gin.H{"error": "Server is unable to generate a key sign challenge"})
		return
	}

    serverSignature, err := signPayload(serverPayload, privateKey)
	if err != nil {
		log.Warningln("Failure when signing the challenge:", err)
		ctx.JSON(500, gin.H{"error": "Failure when signing the challenge"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
        "server_nonce": serverNonce,
        "client_nonce": clientNonce,
        "server_payload": hex.EncodeToString(serverPayload),
        "server_signature": hex.EncodeToString(serverSignature),
    })
}

func jwksToEcdsaPublicKey(jwks map[string]interface{}) *ecdsa.PublicKey {
	x := jwks["x"].(string)
	y := jwks["y"].(string)
	xBigInt, _ := new(big.Int).SetString(x, 10)
	yBigInt, _ := new(big.Int).SetString(y, 10)

	clientPubkey := &ecdsa.PublicKey{
		Curve: elliptic.P521(),
		X:     xBigInt,
		Y:     yBigInt,
	}

	return clientPubkey
}	

func keySignChallengeCommit(ctx *gin.Context, data map[string]interface{}, action string) {
    clientNonce, _ := data["client_nonce"].(string)
    serverNonce, _ := data["server_nonce"].(string)
    jsonPublicKey := data["pubkey"].(map[string]interface{})

	clientPubkey := jwksToEcdsaPublicKey(jsonPublicKey)
	clientPayload := []byte(clientNonce + serverNonce)
	clientSignature, err := hex.DecodeString(data["client_signature"].(string))
	if err != nil {
		log.Warningln("Failed to decode 'client_signature' value:", err)
		ctx.JSON(500, gin.H{"error": "Failed to decode 'client_signature' value"})
		return
	}
	clientVerified := verifySignature(clientPayload, clientSignature, clientPubkey)

	serverPayload, _ := hex.DecodeString(data["server_payload"].(string))
	serverSignature, _ := hex.DecodeString(data["server_signature"].(string))
	serverPrivateKey, err := loadServerKeys()
	if err != nil {
		log.Warningln("Failed to load server private key:", err)
		ctx.JSON(500, gin.H{"error": "Failed to load server private key"})
		return
	}
	serverPubkey := serverPrivateKey.PublicKey
	serverVerified := verifySignature(serverPayload, serverSignature, &serverPubkey)

    if clientVerified && serverVerified {
        if action == "register" {
			log.Debug("Registering namespace", data["prefix"])
			dbAddNamespace(ctx, data)
        } 
    } else {
        ctx.JSON(http.StatusMultipleChoices, gin.H{"status": "Key Sign Challenge FAILED"})
    }
}

/*
Handler functions called upon by the gin router
*/
func cliRegisterNamespace(c *gin.Context) {
	var requestData map[string]interface{}
	if err := c.BindJSON(&requestData); err != nil {
		log.Errorf("Bad Request: %w", err)
		c.JSON(http.StatusBadRequest, gin.H{"status": "Bad Request"})
		return
	}

	accessToken := requestData["access_token"]
	if accessToken != nil && accessToken != "" {
		payload := url.Values{}
		payload.Set("access_token", accessToken.(string))

		resp, err := http.PostForm("https://cilogon.org/oauth2/userinfo", payload)
		if err != nil {
			panic(err)
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		requestData["identity"] = string(body)
		keySignChallenge(c, requestData, "register")
		return 
	}

	identity_required := requestData["identity_required"]

	if identity_required == nil || identity_required == "false" {
		keySignChallenge(c, requestData, "register")
		return 
	}

	device_code := requestData["device_code"]

	OIDCClientIDFile := viper.GetString("OIDCClientIDFile")
	OIDCClientIDFromEnv := viper.GetString("OIDCCLIENTID")
	if OIDCClientIDFile != "" {
		contents, err := os.ReadFile(OIDCClientIDFile)
		if err != nil {
			log.Errorln(err)
		}
		OIDCClientID = strings.TrimSpace(string(contents))
	} else if OIDCClientIDFromEnv != "" {
		OIDCClientID = OIDCClientIDFromEnv
	} else {
		log.Errorln("An OIDC Client Identity file must be specified in the config (OIDCClientIDFile), or the identity must be provided via the environment variable PELICAN_OIDCCLIENTID")
	}

	OIDCClientSecretFile := viper.GetString("OIDCClientSecretFile")
	OIDCClientSecretFromEnv := viper.GetString("OIDCCLIENTSECRET")
	if OIDCClientSecretFile != "" {
		contents, err := os.ReadFile(OIDCClientSecretFile)
		if err != nil {
			log.Errorln(err)
		}
		OIDCClientSecret = strings.TrimSpace(string(contents))
	} else if OIDCClientSecretFromEnv != "" {
		OIDCClientSecret = OIDCClientSecretFromEnv
	} else {
		log.Errorln("An OIDC Client Secret file must be specified in the config (OIDCClientSecretFile), or the secret must be provided via the environment variable PELICAN_OIDCCLIENTSECRET")
	}

	if device_code == nil || device_code == "" {
		log.Debug("Getting Device Code")
		payload := url.Values{}
		payload.Set("client_id", OIDCClientID)
		payload.Set("client_secret", OIDCClientSecret)
		payload.Set("scope", OIDCScope)
	
		response, err := http.PostForm(DeviceAuthEndpoint, payload)
		if err != nil {
			log.Fatalln(err)
		}
		defer response.Body.Close()
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalln(err)
		}
		var res Response
		err = json.Unmarshal(body, &res)
		if err != nil {
			log.Fatalln(err)
		}
		verificationURL := res.VerificationURLComplete
		deviceCode := res.DeviceCode
		c.JSON(http.StatusOK, gin.H{
			"device_code": deviceCode,
			"verification_url": verificationURL,
		})
		return 
	} else {
		log.Debug("Verifying Device Code")
		payload := url.Values{}
		payload.Set("client_id", OIDCClientID)
		payload.Set("client_secret", OIDCClientSecret)
		payload.Set("device_code", device_code.(string))
		payload.Set("grant_type", GrantType)

		response, err := http.PostForm(TokenEndpoint, payload)
		if err != nil {
			log.Fatalln(err)
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatalln(err)
		}

		var tokenResponse TokenResponse
		err = json.Unmarshal(body, &tokenResponse)
		if err != nil {
			log.Fatalln(err)
		}


		if tokenResponse.AccessToken == "" {
			c.JSON(http.StatusOK, gin.H{
				"status": "PENDING",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"status": "APPROVED",
				"access_token": tokenResponse.AccessToken,
			})
		}
		return 
	}
}

func dbAddNamespace(c *gin.Context, data map[string]interface{}) {
	var ns Namespace

	ns.Prefix = data["prefix"].(string)
	pubkeyData, _ := json.Marshal(data["pubkey"].(map[string]interface{}))
	ns.Pubkey = string(pubkeyData)
	if data["identity"] != nil {
		ns.Identity = data["identity"].(string)
	}

	err := addNamespace(&ns)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func dbDeleteNamespace(c *gin.Context) {
	prefix := c.Param("wildcard")

	// A weird feature of gin is that wildcards always
	// add a preceding /. We need to trim it here...
	prefix = strings.TrimPrefix(prefix, "/")
	log.Debug("Attempting to delete prefix", prefix)

	err := deleteNamespace(prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

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

func dbGetAllNamespaces(c *gin.Context) {
	nss, err := getAllNamespaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, nss)
}

func getJwks(c *gin.Context) {
	prefix := c.Param("prefix")
	c.JSON(http.StatusOK, gin.H{"status": "Get JWKS is not implemented", "prefix": prefix})
}

func getOpenIDConfiguration(c *gin.Context) {
	prefix := c.Param("prefix")
	c.JSON(http.StatusOK, gin.H{"status": "getOpenIDConfiguration is not implemented", "prefix": prefix})
}

func RegisterNamespaceRegistry(router *gin.RouterGroup) {
	// Establish various routes to be used by the namespace registry
	router.POST("/cli-namespaces/registry", cliRegisterNamespace)
	router.GET("/cli-namespaces", dbGetAllNamespaces)
	// router.GET("/cli-namespaces/:prefix/issuer.jwks", getJwks)
	// router.GET("/cli-namespaces/:prefix/.well-known/openid-configuration", getOpenIDConfiguration)
	router.DELETE("/cli-namespaces/*wildcard", dbDeleteNamespace)
}
