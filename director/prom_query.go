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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	promQLResData struct {
		ResultType string // "matrix" | "vector" | "scalar" | "string"

		// Result has varying formats depending on the ResultType.
		// See the [expression query result formats]: https://prometheus.io/docs/prometheus/latest/querying/api/#expression-query-result-formats.
		Result []interface{}
	}
	promQLRes struct {
		Status    string // success | error
		Data      promQLResData
		Error     string // only when status == "error"
		ErrorType string // only when status == "error"
	}

	promQLValuePair struct {
		UnixTime float64
		// Numbers are encoded in string to include NaN, Inf, and -Inf.
		// It is the user's responsibility to handle the conversion from string to numbers.
		Value string
	}

	promQLResultItem struct {
		Metric map[string]interface{}
		Values []promQLValuePair
	}

	promQLParsed struct {
		ResultType string // "matrix" | "vector" | "scalar" | "string"
		Result     []promQLResultItem
	}
)

// Query the Prometheus PromQL endpoint on the director server
// at /api/v1.0/prometheus/query?query=
//
// where the only arg is the query to execute, without "?query="
//
// Example: queryPromtheus("up") // Get metric of the running Prometheus instances
func queryPromtheus(ctx context.Context, query string, withToken bool) (promParsed promQLParsed, err error) {
	if strings.HasPrefix(query, "?query=") {
		err = errors.Errorf("query argument should not contain \"?query=\"")
		return
	}
	extWebUrl := param.Server_ExternalWebUrl.GetString()
	baseUrl, err := url.JoinPath(extWebUrl, "/api/v1.0/prometheus/query")
	if err != nil {
		return
	}
	queryUrl := baseUrl + "?query=" + url.QueryEscape(query)

	tk := ""
	if withToken {
		tc := token.NewWLCGToken()
		tc.Issuer = extWebUrl
		tc.Lifetime = time.Minute
		tc.Subject = "director"
		tc.AddAudiences(extWebUrl)
		tc.AddScopes(token_scopes.Monitoring_Query)
		tk, err = tc.CreateToken()
		if err != nil {
			err = errors.Wrap(err, "failed to create token to access PromQL endpoint")
			return
		}
	}

	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryUrl, nil)
	if err != nil {
		return
	}
	if withToken && tk != "" {
		req.Header.Add("Authorization", "Bearer "+tk)
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		err = errors.Wrap(err, "failed to read the body of the response")
		return
	}
	if res.StatusCode != 200 {
		err = errors.Errorf("Prometheus responded %d for the query %q: %s", res.StatusCode, query, string(body))
		return
	}
	promRes := promQLRes{}
	err = json.Unmarshal(body, &promRes)
	if err != nil {
		err = errors.Wrap(err, "failed to parse PromQL response")
		return
	}
	if promRes.Status != "success" {
		err = errors.Errorf("Prometheus responded error for query %q with error type %s: %s", query, promRes.ErrorType, promRes.Error)
		return
	}
	promParsed, err = parsePromRes(promRes)
	if err != nil {
		return
	}
	return
}

// Parse the raw PromQL API response to a unified struct
func parsePromRes(res promQLRes) (promParsed promQLParsed, err error) {
	data := res.Data
	promParsed = promQLParsed{
		ResultType: data.ResultType,
	}

	if data.Result != nil && len(data.Result) > 0 {
		switch data.Result[0].(type) {
		case float64: // result: [unixtime, value]
			if len(data.Result) == 2 && (data.ResultType == "scalar" || data.ResultType == "string") {
				timestamp, ok := data.Result[0].(float64)
				if !ok {
					err = errors.Errorf("parse error for result type %s: failed to convert the first element of the result array to float64", data.ResultType)
					return
				}
				value, ok := data.Result[1].(string)
				if !ok {
					err = errors.Errorf("parse error for result type %s: failed to convert the second element of the result array to string", data.ResultType)
					return
				}
				promParsed.Result = []promQLResultItem{{Values: []promQLValuePair{{UnixTime: timestamp, Value: value}}}}
				return
			} else {
				err = errors.Errorf("parse error: unsupported result type: the first element of the result array is float64 but result type is neither scalar or string")
				return
			}
		case map[string]interface{}:
			if data.ResultType != "vector" && data.ResultType != "matrix" {
				err = errors.Errorf("parse error: unsupported result type: the first element of the result array is an object but result type is neither vector or matrix")
				return
			}
			promParsed.Result = []promQLResultItem{}
			for rIdx, elem := range data.Result {
				obj, ok := elem.(map[string]interface{})
				if !ok {
					err = errors.Errorf("parse error for result type %s: failed to convert the element of the result array to object at %d: %#v", data.ResultType, rIdx, elem)
					return
				}
				// Parse "metric"
				metric, ok := obj["metric"]
				if !ok {
					err = errors.Errorf("parse error for result type %s: metric field does not exist for element at %d: %#v", data.ResultType, rIdx, elem)
					return
				}
				metricObj, ok := metric.(map[string]interface{})
				if !ok {
					err = errors.Errorf("parse error for result type %s: metric field at %d is not a map with string key and interface value: %#v", data.ResultType, rIdx, elem)
					return
				}

				if data.ResultType == "vector" { // result: [{"metric": {}, "value": []}]
					value, ok := obj["value"]
					if !ok {
						err = errors.Errorf("parse error for result type %s: value field does not exist for element at %d: %#v", data.ResultType, rIdx, elem)
						return
					}
					valueArr, ok := value.([]interface{})
					if !ok {
						err = errors.Errorf("parse error for result type %s: value field is not an array for element at %d: %#v", data.ResultType, rIdx, elem)
						return
					}
					if len(valueArr) != 2 {
						err = errors.Errorf("parse error for result type %s: the length of the value field is not 2 for element at %d: %#v", data.ResultType, rIdx, elem)
						return
					}
					unixTime, ok := valueArr[0].(float64)
					if !ok {
						err = errors.Errorf("parse error for result type %s: the first item of the value field is not float64 type for element at %d: %#v", data.ResultType, rIdx, elem)
						return
					}
					vecValue, ok := valueArr[1].(string)
					if !ok {
						err = errors.Errorf("parse error for result type %s: the second item of the value field is not string type for element at %d: %#v", data.ResultType, rIdx, elem)
						return
					}
					vp := []promQLValuePair{{UnixTime: unixTime, Value: vecValue}}
					promParsed.Result = append(promParsed.Result, promQLResultItem{Metric: metricObj, Values: vp})
				} else { // this is a a matrix type. result: [{"metric": {}, "values": [[],[]]}]
					values, ok := obj["values"]
					if !ok {
						err = errors.Errorf("parse error for result type %s: values field does not exist for element at %d: %#v", data.ResultType, rIdx, elem)
						return
					}
					valuesArr, ok := values.([]interface{})
					if !ok {
						err = errors.Errorf("parse error for result type %s: values field is not a matrix for element at %d: %#v", data.ResultType, rIdx, elem)
						return
					}
					vps := []promQLValuePair{}
					if len(valuesArr) != 0 {
						for _, value := range valuesArr {
							valueArr, ok := value.([]interface{})
							if !ok {
								err = errors.Errorf("parse error for result type %s: values field is not a matrix for element at %d: %#v", data.ResultType, rIdx, elem)
								return
							}
							if len(valueArr) != 2 {
								err = errors.Errorf("parse error for result type %s: malformed item for values field for element at %d: %#v", data.ResultType, rIdx, elem)
								return
							}
							unixTime, ok := valueArr[0].(float64)
							if !ok {
								err = errors.Errorf("parse error for result type %s: malformed time for values field for element at %d: %#v", data.ResultType, rIdx, elem)
								return
							}
							vecValue, ok := valueArr[1].(string)
							if !ok {
								err = errors.Errorf("parse error for result type %s: malformed metric value for values field for element at %d: %#v", data.ResultType, rIdx, elem)
								return
							}
							vps = append(vps, promQLValuePair{UnixTime: unixTime, Value: vecValue})
						}
					}
					promParsed.Result = append(promParsed.Result, promQLResultItem{Metric: metricObj, Values: vps})
				}
			}
		default:
			err = errors.Errorf("unsupported value type %T, expected to be either float64 or object: %#v", data.Result[0], data.Result)
			return
		}
	}
	return
}
