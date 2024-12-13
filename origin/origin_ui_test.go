package origin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestSuccessfulCreateNewIssuerKey(t *testing.T) {
	server_utils.ResetTestState()

	tDir := t.TempDir()
	viper.Set("IssuerKeysDirectory", filepath.Join(tDir, "test-issuer-keys"))
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()

	router := gin.Default()
	router.GET("/api/v1.0/origin_ui/newIssuerKey", func(ctx *gin.Context) {
		createNewIssuerKey(ctx, config.GeneratePEM)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1.0/origin_ui/newIssuerKey", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response server_structs.SimpleApiResp
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, server_structs.RespOK, response.Status)
	assert.Equal(t, "Created a new issuer key and set it as the active private key", response.Msg)

}

func TestFailedCreateNewIssuerKey(t *testing.T) {
	server_utils.ResetTestState()

	tDir := t.TempDir()
	viper.Set("IssuerKeysDirectory", filepath.Join(tDir, "test-issuer-keys"))
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()

	router := gin.Default()
	mockErrGeneratePEM := func(directory string) (jwk.Key, error) {
		return nil, assert.AnError
	}
	router.GET("/api/v1.0/origin_ui/newIssuerKey", func(ctx *gin.Context) {
		createNewIssuerKey(ctx, mockErrGeneratePEM)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1.0/origin_ui/newIssuerKey", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response server_structs.SimpleApiResp
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, server_structs.RespFailed, response.Status)
	assert.Equal(t, "Error creating a new private key in a new .pem file", response.Msg)
}
