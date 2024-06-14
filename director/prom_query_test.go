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

package director

import (
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

var (
	//go:embed resources/promql_matrix.json
	promQLMatrix string
	//go:embed resources/promql_vector.json
	promQLVector string
	//go:embed resources/promql_scalar.json
	promQLScalar string
	//go:embed resources/promql_string.json
	promQLString string
)

func TestParsePromRes(t *testing.T) {
	t.Run("parse-scalar-value", func(t *testing.T) {
		mockTimeNow := float64(time.Now().Unix())
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "scalar",
			Result:     []interface{}{mockTimeNow, "1"},
		}}
		res, err := parsePromRes(mockPromQLRes)

		require.NoError(t, err)
		assert.Equal(t, "scalar", res.ResultType)
		assert.NotNil(t, res.Result)
		assert.Len(t, res.Result, 1)
		assert.Nil(t, res.Result[0].Metric)
		assert.Equal(t, mockTimeNow, res.Result[0].Values[0].UnixTime)
		assert.Equal(t, "1", res.Result[0].Values[0].Value)
	})

	t.Run("parse-string-value", func(t *testing.T) {
		mockTimeNow := float64(time.Now().Unix())
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "string",
			Result:     []interface{}{mockTimeNow, "mock string"},
		}}
		res, err := parsePromRes(mockPromQLRes)

		require.NoError(t, err)
		assert.Equal(t, "string", res.ResultType)
		assert.NotNil(t, res.Result)
		assert.Len(t, res.Result, 1)
		assert.Nil(t, res.Result[0].Metric)
		assert.Equal(t, mockTimeNow, res.Result[0].Values[0].UnixTime)
		assert.Equal(t, "mock string", res.Result[0].Values[0].Value)
	})

	t.Run("error-when-unixtime-is-wrong", func(t *testing.T) {
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "string",
			Result:     []interface{}{"misformed-unixtime", "mock string"},
		}}
		_, err := parsePromRes(mockPromQLRes)
		require.Error(t, err)
	})

	t.Run("error-when-value-is-wrong", func(t *testing.T) {
		mockTimeNow := float64(time.Now().Unix())
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "string",
			Result:     []interface{}{mockTimeNow, 2},
		}}
		_, err := parsePromRes(mockPromQLRes)
		require.Error(t, err)
	})

	t.Run("parse-vector-value", func(t *testing.T) {
		mockTimeNow := float64(time.Now().Unix())
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "vector",
			Result: []interface{}{
				map[string]interface{}{
					"metric": map[string]interface{}{"foo": "bar"},
					"value":  []interface{}{mockTimeNow, "1"},
				},
				map[string]interface{}{
					"metric": map[string]interface{}{"barz": "bob"},
					"value":  []interface{}{mockTimeNow, "2"},
				},
			},
		}}
		res, err := parsePromRes(mockPromQLRes)

		require.NoError(t, err)
		assert.Equal(t, "vector", res.ResultType)
		require.NotNil(t, res.Result)
		require.Len(t, res.Result, 2)
		require.NotNil(t, res.Result[0].Metric)
		assert.Equal(t, "bar", res.Result[0].Metric["foo"])
		assert.NotNil(t, res.Result[0].Values)
		assert.Equal(t, mockTimeNow, res.Result[0].Values[0].UnixTime)
		assert.Equal(t, "1", res.Result[0].Values[0].Value)

		require.NotNil(t, res.Result[1].Metric)
		assert.Equal(t, "bob", res.Result[1].Metric["barz"])
		assert.NotNil(t, res.Result[1].Values)
		assert.Equal(t, mockTimeNow, res.Result[1].Values[0].UnixTime)
		assert.Equal(t, "2", res.Result[1].Values[0].Value)
	})

	t.Run("parse-matrix-value", func(t *testing.T) {
		mockTimeNow := float64(time.Now().Unix())
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "matrix",
			Result: []interface{}{
				map[string]interface{}{
					"metric": map[string]interface{}{"foo": "bar"},
					"values": []interface{}{
						[]interface{}{mockTimeNow, "1"},
						[]interface{}{mockTimeNow + 1, "2"},
					},
				},
				map[string]interface{}{
					"metric": map[string]interface{}{"barz": "bob"},
					"values": []interface{}{
						[]interface{}{mockTimeNow, "5"},
						[]interface{}{mockTimeNow + 1, "10"},
					},
				},
			},
		}}
		res, err := parsePromRes(mockPromQLRes)

		require.NoError(t, err)
		assert.Equal(t, "matrix", res.ResultType)
		require.NotNil(t, res.Result)
		require.Len(t, res.Result, 2)
		require.NotNil(t, res.Result[0].Metric)
		assert.Equal(t, "bar", res.Result[0].Metric["foo"])
		assert.NotNil(t, res.Result[0].Values)
		assert.Equal(t, 2, len(res.Result[0].Values))
		assert.Equal(t, mockTimeNow, res.Result[0].Values[0].UnixTime)
		assert.Equal(t, "1", res.Result[0].Values[0].Value)
		assert.Equal(t, mockTimeNow+1, res.Result[0].Values[1].UnixTime)
		assert.Equal(t, "2", res.Result[0].Values[1].Value)

		require.NotNil(t, res.Result[1].Metric)
		assert.Equal(t, "bob", res.Result[1].Metric["barz"])
		assert.NotNil(t, res.Result[1].Values)
		assert.Equal(t, 2, len(res.Result[1].Values))
		assert.Equal(t, mockTimeNow, res.Result[1].Values[0].UnixTime)
		assert.Equal(t, "5", res.Result[1].Values[0].Value)
		assert.Equal(t, mockTimeNow+1, res.Result[1].Values[1].UnixTime)
		assert.Equal(t, "10", res.Result[1].Values[1].Value)
	})

	t.Run("parse-empty-vector-value", func(t *testing.T) {
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "vector",
			Result:     []interface{}{},
		}}
		res, err := parsePromRes(mockPromQLRes)

		require.NoError(t, err)
		require.Nil(t, res.Result)
	})

	t.Run("parse-empty-matrix-value", func(t *testing.T) {
		mockPromQLRes := promQLRes{Data: promQLResData{
			ResultType: "matrix",
			Result:     []interface{}{},
		}}
		res, err := parsePromRes(mockPromQLRes)

		require.NoError(t, err)
		require.Nil(t, res.Result)
	})
}

func TestQueryPrometheus(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	handler := func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if query == "" {
			w.WriteHeader(http.StatusBadRequest)
		}
		w.Header().Add("Content-Type", "application/json")
		switch query {
		case "scalar":
			_, err := w.Write([]byte(promQLScalar))
			require.NoError(t, err)
			return
		case "string":
			_, err := w.Write([]byte(promQLString))
			require.NoError(t, err)
			return
		case "vector":
			_, err := w.Write([]byte(promQLVector))
			require.NoError(t, err)
			return
		case "matrix":
			_, err := w.Write([]byte(promQLMatrix))
			require.NoError(t, err)
			return
		case "error":
			fakeError := `{"status":"error", "error": "bad weather", "errorType": "notInTheMood"}`
			_, err := w.Write([]byte(fakeError))
			require.NoError(t, err)
			return
		case "empty":
			empty := `{"status":"success","data":{"resultType":"vector","result":[]}}`
			_, err := w.Write([]byte(empty))
			require.NoError(t, err)
			return
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	viper.Set(param.Server_ExternalWebUrl.GetName(), server.URL)
	defer server.Close()

	t.Run("no-token-query-matrix", func(t *testing.T) {
		parsed, err := queryPromtheus(context.Background(), "matrix", false)
		require.NoError(t, err)
		assert.Equal(t, "matrix", parsed.ResultType)
		require.Len(t, parsed.Result, 2)
		require.NotNil(t, parsed.Result[0].Metric)
		assert.Equal(t, "up", parsed.Result[0].Metric["__name__"])
		require.NotNil(t, parsed.Result[0].Values)
		require.Len(t, parsed.Result[0].Values, 3)
		assert.Equal(t, "1", parsed.Result[0].Values[0].Value)
		assert.Equal(t, "1", parsed.Result[0].Values[1].Value)
		assert.Equal(t, "1", parsed.Result[0].Values[2].Value)
		assert.Equal(t, 1435781430.781, parsed.Result[0].Values[0].UnixTime)
		assert.Equal(t, 1435781445.781, parsed.Result[0].Values[1].UnixTime)
		assert.Equal(t, 1435781460.781, parsed.Result[0].Values[2].UnixTime)

		require.NotNil(t, parsed.Result[1].Metric)
		assert.Equal(t, "up", parsed.Result[1].Metric["__name__"])
		require.Len(t, parsed.Result[1].Values, 3)
		assert.Equal(t, "0", parsed.Result[1].Values[0].Value)
		assert.Equal(t, "0", parsed.Result[1].Values[1].Value)
		assert.Equal(t, "1", parsed.Result[1].Values[2].Value)
		assert.Equal(t, 1435781430.781, parsed.Result[1].Values[0].UnixTime)
		assert.Equal(t, 1435781445.781, parsed.Result[1].Values[1].UnixTime)
		assert.Equal(t, 1435781460.781, parsed.Result[1].Values[2].UnixTime)
	})

	t.Run("no-token-query-vector", func(t *testing.T) {
		parsed, err := queryPromtheus(context.Background(), "vector", false)
		require.NoError(t, err)
		assert.Equal(t, "vector", parsed.ResultType)
		require.Len(t, parsed.Result, 2)
		require.NotNil(t, parsed.Result[0].Metric)
		assert.Equal(t, "up", parsed.Result[0].Metric["__name__"])
		require.NotNil(t, parsed.Result[0].Values)
		require.Len(t, parsed.Result[0].Values, 1)
		assert.Equal(t, "1", parsed.Result[0].Values[0].Value)
		assert.Equal(t, 1435781451.781, parsed.Result[0].Values[0].UnixTime)

		require.NotNil(t, parsed.Result[1].Metric)
		assert.Equal(t, "up", parsed.Result[1].Metric["__name__"])
		require.Len(t, parsed.Result[1].Values, 1)
		assert.Equal(t, "0", parsed.Result[1].Values[0].Value)
		assert.Equal(t, 1435781451.781, parsed.Result[1].Values[0].UnixTime)
	})

	t.Run("no-token-query-scalar", func(t *testing.T) {
		parsed, err := queryPromtheus(context.Background(), "scalar", false)
		require.NoError(t, err)
		assert.Equal(t, "scalar", parsed.ResultType)
		require.Len(t, parsed.Result, 1)
		require.Nil(t, parsed.Result[0].Metric)
		require.NotNil(t, parsed.Result[0].Values)
		require.Len(t, parsed.Result[0].Values, 1)
		assert.Equal(t, "1", parsed.Result[0].Values[0].Value)
		assert.Equal(t, 1435781451.781, parsed.Result[0].Values[0].UnixTime)
	})

	t.Run("no-token-query-string", func(t *testing.T) {
		parsed, err := queryPromtheus(context.Background(), "string", false)
		require.NoError(t, err)
		assert.Equal(t, "string", parsed.ResultType)
		require.Len(t, parsed.Result, 1)
		require.Nil(t, parsed.Result[0].Metric)
		require.NotNil(t, parsed.Result[0].Values)
		require.Len(t, parsed.Result[0].Values, 1)
		assert.Equal(t, "this is a string", parsed.Result[0].Values[0].Value)
		assert.Equal(t, 1435781451.781, parsed.Result[0].Values[0].UnixTime)
	})

	t.Run("no-token-query-prom-error", func(t *testing.T) {
		_, err := queryPromtheus(context.Background(), "error", false)
		assert.Error(t, err)
		require.Equal(t, "Prometheus responded error for query \"error\" with error type notInTheMood: bad weather", err.Error())
	})

	t.Run("no-token-query-empty-data", func(t *testing.T) {
		parsed, err := queryPromtheus(context.Background(), "empty", false)
		assert.NoError(t, err)
		assert.Nil(t, parsed.Result)
		assert.Equal(t, "vector", parsed.ResultType) // default type is vector
	})
}
