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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestInitInstConfig(t *testing.T) {
	institutionsCache = ttlcache.New[string, []Institution]()
	t.Run("wrong-inst-config-returns-error", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockWrongInst := []mockBadInstitutionFormat{{RORID: "mockID", Inst: "mockInst"}}
		// YAML is also incorrect format, viper is expecting mapstructure
		mockWrongInstByte, err := yaml.Marshal(mockWrongInst)
		require.NoError(t, err)
		viper.Set("Registry.Institutions", mockWrongInstByte)
		err = InitInstConfig(ctx, egrp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Fail to read Registry.Institutions.")
	})

	t.Run("valid-inst-config-with-dup-ids-returns-err", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockMap := make(map[string]string)
		mockMap["ID"] = "mockID"
		mockMap["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap, mockMap})
		err := InitInstConfig(ctx, egrp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Institution IDs read from config are not unique")
	})

	t.Run("valid-inst-config-with-unique-ids", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockMap1 := make(map[string]string)
		mockMap1["ID"] = "mockID"
		mockMap1["Name"] = "mockName"
		mockMap2 := make(map[string]string)
		mockMap2["ID"] = "mockID2"
		mockMap2["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap1, mockMap2})
		err := InitInstConfig(ctx, egrp)
		require.NoError(t, err)
	})

	t.Run("config-val-url-both-set-gives-config", func(t *testing.T) {
		institutionsCache = nil
		defer func() {
			institutionsCache = ttlcache.New[string, []Institution]()
		}()

		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		mockMap1 := make(map[string]string)
		mockMap1["ID"] = "mockID"
		mockMap1["Name"] = "mockName"
		mockMap2 := make(map[string]string)
		mockMap2["ID"] = "mockID2"
		mockMap2["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap1, mockMap2})
		viper.Set("Registry.InstitutionsUrl", "https://example.com")
		err := InitInstConfig(ctx, egrp)
		require.NoError(t, err)
		// This means we didn't config ttl cache
		require.Nil(t, institutionsCache)
		require.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, "Registry.Institutions and Registry.InstitutionsUrl are both set. Registry.InstitutionsUrl is ignored", hook.LastEntry().Message)
	})

	t.Run("valid-inst-config-with-dup-ids-and-url-returns-err", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()
		viper.Reset()
		mockMap := make(map[string]string)
		mockMap["ID"] = "mockID"
		mockMap["Name"] = "mockName"
		viper.Set("Registry.Institutions", []map[string]string{mockMap, mockMap})
		viper.Set("Registry.InstitutionsUrl", "https://example.com")
		err := InitInstConfig(ctx, egrp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Institution IDs read from config are not unique")
	})

	t.Run("only-url-set-with-invalid-data-is-non-blocking", func(t *testing.T) {
		institutionsCache = nil
		defer func() {
			institutionsCache = ttlcache.New[string, []Institution]()
		}()

		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		viper.Reset()
		logrus.SetLevel(logrus.WarnLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// Invalid URL
		viper.Set("Registry.InstitutionsUrl", "https://example.com")
		err := InitInstConfig(ctx, egrp)
		// No error should return, this is non-blcoking
		require.NoError(t, err)
		require.Equal(t, 1, len(hook.Entries))
		assert.Contains(t, hook.LastEntry().Message, "Failed to populate institution cache.")
		assert.NotNil(t, institutionsCache)
	})

	t.Run("only-url-set-with-valid-data", func(t *testing.T) {
		institutionsCache = nil
		defer func() {
			institutionsCache = ttlcache.New[string, []Institution]()
		}()
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// Valid URL, Although very dangerous to do so
		viper.Set("Registry.InstitutionsUrl", "https://topology.opensciencegrid.org/institution_ids")
		err := InitInstConfig(ctx, egrp)
		// No error should return, this is non-blcoking
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(hook.Entries), 1)
		assert.Contains(t, hook.LastEntry().Message, "Successfully populated institution TTL cache")
		assert.NotNil(t, institutionsCache)
		assert.GreaterOrEqual(t, institutionsCache.Len(), 1)
	})
}

func TestGetCachedInstitutions(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/institution_ids" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`[{"id": "https://osg-htc.org/iid/05ejpqr48", "name": "Worcester Polytechnic Institute", "ror_id": "https://ror.org/05ejpqr48"}, {"id": "https://osg-htc.org/iid/017t4sb47", "name": "Wright Institute", "ror_id": "https://ror.org/017t4sb47"}, {"id": "https://osg-htc.org/iid/03v76x132", "name": "Yale University", "ror_id": "https://ror.org/03v76x132"}]`))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	// Hijack the common transport used by Pelican, forcing all connections to go to our test server
	transport := config.GetTransport()
	oldDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, svr.Listener.Addr().Network(), svr.Listener.Addr().String())
	}
	oldConfig := transport.TLSClientConfig
	transport.TLSClientConfig = svr.TLS.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	t.Cleanup(func() {
		transport.DialContext = oldDial
		transport.TLSClientConfig = oldConfig
	})

	t.Run("nil-cache-returns-error", func(t *testing.T) {
		institutionsCache = nil
		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		assert.Equal(t, "institutionsCache isn't initialized", intErr.Error())
	})

	t.Run("unset-config-val-returns-error", func(t *testing.T) {
		viper.Reset()
		institutionsCache = ttlcache.New[string, []Institution]()
		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		assert.Contains(t, intErr.Error(), "Registry.InstitutionsUrl is unset")
	})

	t.Run("random-config-val-returns-error", func(t *testing.T) {
		viper.Reset()
		viper.Set("Registry.InstitutionsUrl", "random-url")
		institutionsCache = ttlcache.New[string, []Institution]()
		_, intErr, extErr := getCachedInstitutions()
		assert.Error(t, intErr)
		assert.Error(t, extErr)
		// See url.URL for why it won't return error
		assert.Contains(t, intErr.Error(), "Error response when fetching institution list")
	})

	t.Run("cache-hit-with-invalid-ns-returns-error", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		institutionsCache = ttlcache.New[string, []Institution]()
		institutionsCache.Set(mockUrl.String(), nil, ttlcache.NoTTL)

		_, intErr, extErr := getCachedInstitutions()
		require.Error(t, intErr)
		require.Error(t, extErr)
		assert.Contains(t, intErr.Error(), "value is nil from key")

		institutionsCache.DeleteAll()
	})

	t.Run("cache-hit-with-valid-ns", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		mockInsts := []Institution{{Name: "Foo", ID: "001"}}

		institutionsCache = ttlcache.New[string, []Institution]()
		institutionsCache.Set(mockUrl.String(), mockInsts, ttlcache.NoTTL)

		getInsts, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Equal(t, mockInsts, getInsts)

		institutionsCache.DeleteAll()
	})

	t.Run("cache-hit-with-expired-item", func(t *testing.T) {
		viper.Reset()
		mockUrl := url.URL{Scheme: "https", Host: "example.com"}
		viper.Set("Registry.InstitutionsUrl", mockUrl.String())
		mockInsts := []Institution{{Name: "Foo", ID: "001"}}

		institutionsCache = ttlcache.New[string, []Institution]()
		// Expired but never evicted, so Has() still returns true
		institutionsCache.Set(mockUrl.String(), mockInsts, time.Second)

		time.Sleep(2 * time.Second)
		getInsts, intErr, extErr := getCachedInstitutions()
		require.Error(t, intErr)
		require.Error(t, extErr)
		assert.Equal(t, "Fail to get institutions from internal cache, key might be expired", extErr.Error())
		assert.Equal(t, 0, len(getInsts))

		institutionsCache.DeleteAll()
	})

	t.Run("cache-miss-with-success-fetch", func(t *testing.T) {
		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// This is dangerous as we rely on external API to decide if the test succeeds,
		// but this is the one way to test with our custom http client
		viper.Set("Registry.InstitutionsUrl", "https://topology.opensciencegrid.org/institution_ids")
		institutionsCache = ttlcache.New[string, []Institution]()

		getInsts, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Greater(t, len(getInsts), 0)
		assert.Equal(t, 1, len(hook.Entries))
		assert.Contains(t, hook.LastEntry().Message, "Cache miss for institutions TTL cache")

		institutionsCache.DeleteAll()
	})

	t.Run("cache-miss-with-404-fetch", func(t *testing.T) {
		viper.Reset()

		viper.Set("Registry.InstitutionsUrl", "https://example.com/foo.bar")
		institutionsCache = ttlcache.New[string, []Institution]()

		getInsts, intErr, extErr := getCachedInstitutions()
		require.Error(t, intErr)
		require.Error(t, extErr)
		assert.Equal(t, "Error response when fetching institution list with code 404", intErr.Error())
		assert.Equal(t, len(getInsts), 0)

		institutionsCache.DeleteAll()
	})

	t.Run("cache-hit-with-two-success-fetch", func(t *testing.T) {
		viper.Reset()
		logrus.SetLevel(logrus.InfoLevel)
		hook := test.NewGlobal()
		defer hook.Reset()

		// This is dangerous as we rely on external API to decide if the test succeeds,
		// but this is the one way to test with our custom http client
		viper.Set("Registry.InstitutionsUrl", "https://topology.opensciencegrid.org/institution_ids")
		institutionsCache = ttlcache.New[string, []Institution]()

		getInsts, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Greater(t, len(getInsts), 0)
		assert.Equal(t, 1, len(hook.Entries))
		assert.Contains(t, hook.LastEntry().Message, "Cache miss for institutions TTL cache")

		hook.Reset()

		getInsts2, intErr, extErr := getCachedInstitutions()
		require.NoError(t, intErr)
		require.NoError(t, extErr)
		assert.Greater(t, len(getInsts2), 0)
		assert.Equal(t, getInsts, getInsts2)
		// No cache miss
		assert.Equal(t, 0, len(hook.Entries))

		institutionsCache.DeleteAll()
	})
}

func TestCheckUniqueInstitutions(t *testing.T) {
	t.Run("empty-gives-true", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{})
		assert.True(t, unique)
	})

	t.Run("unique-gives-true", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{{ID: "1"}, {ID: "2"}})
		assert.True(t, unique)
	})

	t.Run("duplicated-gives-false", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{{ID: "1"}, {ID: "1"}})
		assert.False(t, unique)
	})

	t.Run("large-entries", func(t *testing.T) {
		unique := checkUniqueInstitutions([]Institution{
			{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "4"}, {ID: "1"},
		})
		assert.False(t, unique)
	})
}
