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

package origin_ui

import (
	"bufio"
	"crypto/ecdsa"
	"embed"
	"fmt"
	"math/rand"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type (
	Login struct {
		User     string `form:"user"`
		Password string `form:"password"`
	}

	InitLogin struct {
		Code string `form:"code"`
	}

	PasswordReset struct {
		Password string `form:"password"`
	}
)

var (
	authDB       atomic.Pointer[htpasswd.File]
	currentCode  atomic.Pointer[string]
	previousCode atomic.Pointer[string]

	//go:embed src/out/*
	webAssets embed.FS
)

func doReload() error {
	db := authDB.Load()
	if db == nil {
		log.Debug("Cannot reload auth database - not configured")
		return nil
	}
	err := db.Reload(nil)
	if err != nil {
		log.Warningln("Failed to reload auth database:", err)
		return err
	}
	log.Debug("Successfully reloaded the auth database")
	return nil
}

func periodicReload() {
	for {
		time.Sleep(30 * time.Second)
		log.Debug("Reloading the auth database")
		_ = doReload()
	}
}

func WaitUntilLogin() error {
	if authDB.Load() != nil {
		return nil
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	hostname := viper.GetString("Hostname")
	webPort := config.WebPort.GetInt()
	isTTY := false
	if term.IsTerminal(int(os.Stdout.Fd())) {
		isTTY = true
		fmt.Printf("\n\n\n\n")
	}

	for {
		previousCode.Store(currentCode.Load())
		newCode := fmt.Sprintf("%06v", rand.Intn(1000000))
		currentCode.Store(&newCode)
		if isTTY {
			fmt.Printf("\033[A\033[A\033[A\033[A")
			fmt.Printf("\033[2K\n")
			fmt.Printf("\033[2K\rPelican admin interface is not initialized\n\033[2KTo initialize, "+
				"login at \033[1;34mhttps://%v:%v/view/initialization/code/\033[0m with the following code:\n",
				hostname, webPort)
			fmt.Printf("\033[2K\r\033[1;34m%v\033[0m\n", *currentCode.Load())
		} else {
			fmt.Printf("Pelican admin interface is not initialized\n To initialize, login at https://%v:%v/view/initialization/code/ with the following code:\n", hostname, webPort)
			fmt.Println(*currentCode.Load())
		}
		start := time.Now()
		for time.Since(start) < 30*time.Second {
			select {
			case <-sigs:
				return errors.New("Process terminated...")
			default:
				time.Sleep(100 * time.Millisecond)
			}
			if authDB.Load() != nil {
				return nil
			}
		}
	}
}

func writePasswordEntry(user, password string) error {
	fileName := viper.GetString("OriginUI.PasswordFile")
	passwordBytes := []byte(password)
	if len(passwordBytes) > 72 {
		return errors.New("Password too long")
	}
	hashed, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	entry := user + ":" + string(hashed) + "\n"

	directory := filepath.Dir(fileName)
	err = os.MkdirAll(directory, 0750)
	if err != nil {
		return err
	}
	fp, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer fp.Close()
	if _, err = fp.Write([]byte(entry)); err != nil {
		return err
	}

	db := authDB.Load()
	if db != nil {
		if db.Reload(nil) != nil {
			return err
		}
	}
	return nil
}

func configureAuthDB() error {
	fileName := viper.GetString("OriginUI.PasswordFile")
	if fileName == "" {
		return errors.New("Location of password file not set")
	}
	fp, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer fp.Close()
	scanner := bufio.NewScanner(fp)
	scanner.Split(bufio.ScanLines)
	hasAdmin := false
	for scanner.Scan() {
		user := strings.Split(scanner.Text(), ":")[0]
		if user == "admin" {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		return errors.New("AuthDB does not have 'admin' user")
	}

	auth, err := htpasswd.New(fileName, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	if err != nil {
		return err
	}
	authDB.Store(auth)

	return nil
}

func setLoginCookie(ctx *gin.Context, user string) {
	key, err := config.GetOriginJWK()
	if err != nil {
		log.Errorln("Failure when loading the cookie signing key:", err)
		ctx.JSON(500, gin.H{"error": "Unable to create login cookies"})
		return
	}

	issuerURL := url.URL{}
	issuerURL.Scheme = "https"
	issuerURL.Host = ctx.Request.URL.Host
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(issuerURL.String()).
		IssuedAt(now).
		Expiration(now.Add(30 * time.Minute)).
		NotBefore(now).
		Subject(user).
		Build()
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to build token"})
		return
	}
	log.Debugf("Type of *key: %T\n", key)
	var raw ecdsa.PrivateKey
	if err = (*key).Raw(&raw); err != nil {
		ctx.JSON(500, gin.H{"error": "Unable to sign login cookie"})
		return
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, raw))
	if err != nil {
		log.Errorln("Failure when signing the login cookie:", err)
		ctx.JSON(500, gin.H{"error": "Unable to sign login cookie"})
		return
	}

	ctx.SetCookie("login", string(signed), 30*60, "/api/v1.0/origin-ui",
		ctx.Request.URL.Host, true, true)
	ctx.SetSameSite(http.SameSiteStrictMode)
}

func getUser(ctx *gin.Context) (string, error) {
	token, err := ctx.Cookie("login")
	if err != nil {
		return "", nil
	}
	key, err := config.GetOriginJWK()
	if err != nil {
		return "", err
	}
	var raw ecdsa.PrivateKey
	if err = (*key).Raw(&raw); err != nil {
		return "", errors.New("Failed to extract cookie signing key")
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.ES512, raw.PublicKey))
	if err != nil {
		return "", err
	}
	if err = jwt.Validate(parsed); err != nil {
		return "", err
	}
	return parsed.Subject(), nil
}

func authHandler(ctx *gin.Context) {
	user, err := getUser(ctx)
	if err != nil {
		log.Errorln("Unable to parse user cookie:", err)
	} else {
		ctx.Set("User", user)
	}
	ctx.Next()
}

func loginHandler(ctx *gin.Context) {
	db := authDB.Load()
	if db == nil {
		newPath := path.Join(ctx.Request.URL.Path, "..", "initLogin")
		initUrl := ctx.Request.URL
		initUrl.Path = newPath
		ctx.Redirect(307, initUrl.String())
		return
	}

	login := Login{}
	if ctx.ShouldBind(&login) != nil {
		ctx.JSON(400, gin.H{"error": "Missing user/password in form data"})
		return
	}
	if !db.Match(login.User, login.Password) {
		ctx.JSON(401, gin.H{"error": "Login failed"})
		return
	}

	setLoginCookie(ctx, login.User)
	ctx.JSON(200, gin.H{"msg": "Success"})
}

func initLoginHandler(ctx *gin.Context) {
	db := authDB.Load()
	if db != nil {
		ctx.JSON(400, gin.H{"error": "Authentication is already initialized"})
		return
	}
	curCode := currentCode.Load()
	if curCode == nil {
		ctx.JSON(400, gin.H{"error": "Code-based login is not available"})
		return
	}
	prevCode := previousCode.Load()

	code := InitLogin{}
	if ctx.ShouldBind(&code) != nil {
		ctx.JSON(400, gin.H{"error": "Login code not provided"})
		return
	}

	if code.Code != *curCode && (prevCode == nil || code.Code != *prevCode) {
		ctx.JSON(401, gin.H{"error": "Invalid login code"})
		return
	}

	setLoginCookie(ctx, "admin")
}

func resetLoginHandler(ctx *gin.Context) {
	passwordReset := PasswordReset{}
	if ctx.ShouldBind(&passwordReset) != nil {
		ctx.JSON(400, gin.H{"error": "Invalid password reset request"})
		return
	}

	user := ctx.GetString("User")
	if user == "" {
		ctx.JSON(403, gin.H{"error": "Password reset only available to logged-in users"})
		return
	}

	if err := writePasswordEntry(user, passwordReset.Password); err != nil {
		log.Errorf("Password reset for user %s failed: %s", user, err)
		ctx.JSON(500, gin.H{"error": "Failed to reset password"})
	} else {
		log.Infof("Password reset for user %s was successful", user)
		ctx.JSON(200, gin.H{"msg": "Success"})
	}
	if err := configureAuthDB(); err != nil {
		log.Errorln("Error in reloading authDB:", err)
	}
}

func ConfigureOriginUI(router *gin.Engine) error {
	if router == nil {
		return errors.New("Origin configuration passed a nil pointer")
	}

	if err := configureAuthDB(); err != nil {
		log.Infoln("Authorization not configured (non-fatal):", err)
	}

	group := router.Group("/api/v1.0/origin-ui", authHandler)
	group.POST("/login", loginHandler)
	group.POST("/initLogin", initLoginHandler)
	group.POST("/resetLogin", resetLoginHandler)
	group.GET("/whoami", func(ctx *gin.Context) {
		user := ctx.GetString("User")
		if user == "" {
			ctx.JSON(200, gin.H{"authenticated": false})
		} else {
			ctx.JSON(200, gin.H{"authenticated": true, "user": user})
		}
	})
	group.GET("/loginInitialized", func(ctx *gin.Context) {
		db := authDB.Load()
		if db == nil {
			ctx.JSON(200, gin.H{"initialized": false})
		} else {
			ctx.JSON(200, gin.H{"initialized": true})
		}
	})

	router.GET("/view/*path", func(ctx *gin.Context) {
		path := ctx.Param("path")

		if strings.HasSuffix(path, "/") {
			path += "index.html"
		}

		filePath := "src/out" + path
		file, _ := webAssets.ReadFile(filePath)
		ctx.Data(
			http.StatusOK,
			mime.TypeByExtension(filePath),
			file,
		)
	})

	// Redirect root to /view for now
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/view/")
	})

	go periodicReload()

	return nil
}
