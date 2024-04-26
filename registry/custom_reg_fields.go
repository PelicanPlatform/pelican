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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	Institution struct {
		Name string `mapstructure:"name" json:"name" yaml:"name"`
		ID   string `mapstructure:"id" json:"id" yaml:"id"`
	}

	customRegFieldsConfig struct {
		Name        string                    `mapstructure:"name"`
		Type        string                    `mapstructure:"type"`
		Required    bool                      `mapstructure:"required"`
		Options     []registrationFieldOption `mapstructure:"options"`
		Description string                    `mapstructure:"description"`
		OptionsUrl  string                    `mapstructure:"optionsUrl"`
	}
)

var (
	customRegFieldsConfigs []customRegFieldsConfig
	institutionsCache      *ttlcache.Cache[string, []Institution]
	optionsCache           = ttlcache.New(
		ttlcache.WithTTL[string, []registrationFieldOption](5 * time.Minute),
	)
)

func InitOptionsCache(ctx context.Context, egrp *errgroup.Group) {
	go optionsCache.Start()

	egrp.Go(func() error {
		<-ctx.Done()
		optionsCache.DeleteAll()
		optionsCache.Stop()
		return nil
	})
}

func optionsToString(options []registrationFieldOption) (result string) {
	for _, opt := range options {
		result += fmt.Sprintf("ID: %s | Name: %s\n", opt.ID, opt.Name)
	}
	return
}

// Fetch from the optionsUrl, check the returned options, and set the optionsCache
func getCachedOptions(key string) ([]registrationFieldOption, error) {
	if optionsCache.Has(key) {
		return optionsCache.Get(key).Value(), nil
	}
	// Fetch from URL
	if key == "" {
		return nil, errors.New("key is empty")
	}
	_, err := url.Parse(key)
	if err != nil {
		return nil, errors.Wrap(err, "key is not a valid URL")
	}
	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequest(http.MethodGet, key, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create a new request for fetching key %s", key)
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to request the key %s", key)
	}
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read the response body")
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetching key %s returns status code %d with response body %s", key, res.StatusCode, resBody)
	}
	options := []registrationFieldOption{}
	err = json.Unmarshal(resBody, &options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse response from key %s to options struct with response body: %s", key, resBody)
	}
	isUnique := checkUniqueOptions(options)
	if !isUnique {
		return nil, fmt.Errorf("returned options from key %s are not unique. Options: %s", key, optionsToString(options))
	}
	// Check IDs are not empty
	invalidName := ""
	for _, opt := range options {
		if opt.ID == "" {
			invalidName = opt.Name
			break
		}
	}
	if invalidName != "" {
		return nil, fmt.Errorf("returned options from key %s have empty ID for option %s", key, invalidName)
	}
	optionsCache.Set(key, options, ttlcache.DefaultTTL)
	return options, nil
}

// Given the custom registration fields read from the config,
// convert them to an array of registrationField for web UI
func convertCustomRegFields(configFields []customRegFieldsConfig) []registrationField {
	regFields := make([]registrationField, 0)
	for _, field := range configFields {
		optionsUrl := field.OptionsUrl
		options := field.Options
		if field.Type == string(Enum) {
			if len(options) != 0 { // Options overwrites OptionsUrl
				optionsUrl = ""
			}
			if optionsUrl != "" { // field.Options is not set but OptionsUrl is set
				fetchedOptions, err := getCachedOptions(optionsUrl)
				if err != nil {
					log.Errorf("failed to get OptionsUrl %s for custom field %s", optionsUrl, field.Name)
				} else {
					options = fetchedOptions
				}
			}
		}
		customRegField := registrationField{
			Name:          "custom_fields." + field.Name,
			DisplayedName: utils.SnakeCaseToHumanReadable(field.Name),
			Type:          registrationFieldType(field.Type),
			Options:       options,
			Required:      field.Required,
			Description:   field.Description,
			OptionsUrl:    optionsUrl,
		}
		regFields = append(regFields, customRegField)
	}
	return regFields
}

// Helper function to exclude pubkey field from marshaling into json
func excludePubKey(nss []*Namespace) (nssNew []NamespaceWOPubkey) {
	nssNew = make([]NamespaceWOPubkey, 0)
	for _, ns := range nss {
		nsNew := NamespaceWOPubkey{
			ID:            ns.ID,
			Prefix:        ns.Prefix,
			Pubkey:        ns.Pubkey,
			AdminMetadata: ns.AdminMetadata,
			Identity:      ns.Identity,
		}
		nssNew = append(nssNew, nsNew)
	}

	return
}

func checkUniqueOptions(options []registrationFieldOption) bool {
	repeatMap := make(map[string]bool)
	for _, options := range options {
		if repeatMap[options.ID] {
			return false
		} else {
			repeatMap[options.ID] = true
		}
	}
	return true
}

func checkUniqueInstitutions(insts []Institution) bool {
	repeatMap := make(map[string]bool)
	for _, inst := range insts {
		if repeatMap[inst.ID] {
			return false
		} else {
			repeatMap[inst.ID] = true
		}
	}
	return true
}

// Format custom registration fields in-place, by converting any float64/32 number to int
func formatCustomFields(customFields map[string]interface{}) {
	for key, val := range customFields {
		switch v := val.(type) {
		case float64:
			customFields[key] = int(v)
		case float32:
			customFields[key] = int(v)
		}
	}
}

// Returns the institution options that are fetched from Registry.InstitutionsUrl
// and stored in a TTL cache
func getCachedInstitutions() (inst []Institution, intError error, extError error) {
	if institutionsCache == nil {
		return nil, errors.New("institutionsCache isn't initialized"), errors.New("Internal institution cache wasn't initialized")
	}
	instUrlStr := param.Registry_InstitutionsUrl.GetString()
	if instUrlStr == "" {
		intError = errors.New("Bad server configuration. Registry.InstitutionsUrl is unset")
		extError = errors.New("Bad server configuration. Registry.InstitutionsUrl is unset")
		return
	}
	instUrl, err := url.Parse(instUrlStr)
	if err != nil {
		intError = errors.Wrap(err, "Bad server configuration. Registry.InstitutionsUrl is invalid")
		extError = errors.New("Bad server configuration. Registry.InstitutionsUrl is invalid")
		return
	}
	if !institutionsCache.Has(instUrl.String()) {
		log.Info("Cache miss for institutions TTL cache. Will fetch from source.")
		client := &http.Client{Transport: config.GetTransport()}
		req, err := http.NewRequest(http.MethodGet, instUrl.String(), nil)
		if err != nil {
			intError = errors.Wrap(err, "Error making a request when fetching institution list")
			extError = errors.New("Error when creating a request to fetch institution from remote url.")
			return
		}
		res, err := client.Do(req)
		if err != nil {
			intError = errors.Wrap(err, "Error response when fetching institution list")
			extError = errors.New("Error from response when fetching institution from remote url.")
			return
		}
		if res.StatusCode != 200 {
			intError = errors.New(fmt.Sprintf("Error response when fetching institution list with code %d", res.StatusCode))
			extError = errors.New(fmt.Sprint("Error when fetching institution from remote url, remote server error with code: ", res.StatusCode))
			return
		}
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			intError = errors.Wrap(err, "Error reading response body when fetching institution list")
			extError = errors.New("Error read response when fetching institution from remote url.")
			return
		}
		institutions := []Institution{}
		if err = json.Unmarshal(resBody, &institutions); err != nil {
			intError = errors.Wrap(err, "Error parsing response body when fetching institution list")
			extError = errors.New("Error parsing response when fetching institution from remote url.")
			return
		}
		institutionsCache.Set(instUrl.String(), institutions, ttlcache.DefaultTTL)
		return institutions, nil, nil
	} else {
		institutions := institutionsCache.Get(instUrl.String())
		// institutions == nil if key DNE or item has expired
		if institutions == nil || institutions.Value() == nil {
			intError = errors.New(fmt.Sprint("Fail to get institutions from internal TTL cache, key is nil or value is nil from key: ", instUrl))
			extError = errors.New("Fail to get institutions from internal cache, key might be expired")
			return
		}
		return institutions.Value(), nil, nil
	}
}

// Initialize institutions list
func InitInstConfig(ctx context.Context, egrp *errgroup.Group) error {
	institutions := []Institution{}
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		log.Error("Fail to read Registry.Institutions. Make sure you had the correct format", err)
		return errors.Wrap(err, "Fail to read Registry.Institutions. Make sure you had the correct format")
	}

	if param.Registry_InstitutionsUrl.GetString() != "" {
		// Read from Registry.Institutions if Registry.InstitutionsUrl is empty
		// or Registry.Institutions and Registry.InstitutionsUrl are both set
		if len(institutions) > 0 {
			log.Warning("Registry.Institutions and Registry.InstitutionsUrl are both set. Registry.InstitutionsUrl is ignored")
			if !checkUniqueInstitutions(institutions) {
				return errors.Errorf("Institution IDs read from config are not unique")
			}
			// return here so that we don't init the institution url cache
			return nil
		}

		_, err := url.Parse(param.Registry_InstitutionsUrl.GetString())
		if err != nil {
			log.Error("Invalid Registry.InstitutionsUrl: ", err)
			return errors.Wrap(err, "Invalid Registry.InstitutionsUrl")
		}
		instCacheTTL := param.Registry_InstitutionsUrlReloadMinutes.GetDuration()

		institutionsCache = ttlcache.New[string, []Institution](ttlcache.WithTTL[string, []Institution](instCacheTTL))

		go institutionsCache.Start()

		egrp.Go(func() error {
			<-ctx.Done()
			log.Info("Gracefully stopping institution TTL cache eviction...")
			if institutionsCache != nil {
				institutionsCache.DeleteAll()
				institutionsCache.Stop()
			} else {
				log.Info("Institution TTL cache is nil, stop clean up process.")
			}
			return nil
		})

		// Try to populate the cache at the server start. If error occurred, it's non-blocking
		cachedInsts, intErr, _ := getCachedInstitutions()
		if intErr != nil {
			log.Warning("Failed to populate institution cache. Error: ", intErr)
		} else {
			if !checkUniqueInstitutions(cachedInsts) {
				return errors.Errorf("Institution IDs read from config are not unique")
			}
			log.Infof("Successfully populated institution TTL cache with %d entries", len(institutionsCache.Get(institutionsCache.Keys()[0]).Value()))
		}
	}

	if !checkUniqueInstitutions(institutions) {
		return errors.Errorf("Institution IDs read from config are not unique")
	}
	// Else we will read from Registry.Institutions. No extra action needed.
	return nil
}

// Initialize custom registration fields provided via Registry.CustomRegistrationFields
func InitCustomRegistrationFields() error {
	configFields := []customRegFieldsConfig{}
	if err := param.Registry_CustomRegistrationFields.Unmarshal(&configFields); err != nil {
		return errors.Wrap(err, "Error reading from config value for Registry.CustomRegistrationFields")
	}
	customRegFieldsConfigs = configFields

	fieldNames := make(map[string]bool, 0)

	for _, conf := range configFields {
		// Duplicated name check
		if fieldNames[conf.Name] {
			return errors.New(fmt.Sprintf("Bad custom registration fields, duplicated field name: %q", conf.Name))
		} else {
			fieldNames[conf.Name] = true
		}
		if conf.Type != "string" && conf.Type != "bool" && conf.Type != "int" && conf.Type != "enum" && conf.Type != "datetime" {
			return errors.New(fmt.Sprintf("Bad custom registration field, unsupported field type: %q with %q", conf.Name, conf.Type))
		}
		if conf.Type == "enum" {
			if (conf.Options == nil || len(conf.Options) == 0) && conf.OptionsUrl == "" {
				return errors.New(fmt.Sprintf("Bad custom registration field, 'enum' type field does not have options or optionsUrl set: %q", conf.Name))
			}
		}
	}

	additionalRegFields := convertCustomRegFields(configFields)
	registrationFields = append(registrationFields, additionalRegFields...)

	return nil
}
