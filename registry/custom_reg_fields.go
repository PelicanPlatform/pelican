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
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

type (
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
func getCachedOptions(key string, ttl time.Duration) ([]registrationFieldOption, error) {
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
	isUnique, err := checkUniqueOptions(options)
	if !isUnique {
		return nil, errors.Wrapf(err, "returned options from key %s are not unique", key)
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
	optionsCache.Set(key, options, ttl)
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
				fetchedOptions, err := getCachedOptions(optionsUrl, ttlcache.DefaultTTL)
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
func excludePubKey(nss []server_structs.Namespace) (nssNew []NamespaceWOPubkey) {
	nssNew = make([]NamespaceWOPubkey, 0)
	for _, ns := range nss {
		nsNew := NamespaceWOPubkey{
			ID:               ns.ID,
			Prefix:           ns.Prefix,
			Pubkey:           ns.Pubkey,
			AdminMetadata:    ns.AdminMetadata,
			Identity:         ns.Identity,
			ProhibitedCaches: ns.ProhibitedCaches,
		}
		nssNew = append(nssNew, nsNew)
	}

	return
}

func checkUniqueOptions(options []registrationFieldOption) (bool, error) {
	idMap := make(map[string]bool)
	nameMap := make(map[string]bool)
	for _, options := range options {
		if idMap[options.ID] {
			return false, fmt.Errorf("option IDs are not unique: %s", options.ID)
		} else {
			idMap[options.ID] = true
		}
		if nameMap[options.Name] {
			return false, fmt.Errorf("option names are not unique: %s", options.Name)
		} else {
			nameMap[options.Name] = true
		}
	}
	return true, nil
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

// Initialize institutions list
func InitInstConfig(ctx context.Context, egrp *errgroup.Group) error {
	institutions := []registrationFieldOption{}
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		log.Error("Fail to read Registry.Institutions. Make sure you had the correct format", err)
		return errors.Wrap(err, "Fail to read Registry.Institutions. Make sure you had the correct format")
	}

	instRegIdx := -1 // From the registrationFields, find the index of the field admin_metadata.institution

	for idx, reg := range registrationFields {
		if reg.Name == "admin_metadata.institution" {
			instRegIdx = idx
			registrationFields[idx].Options = institutions
		}
	}

	if instRegIdx == -1 {
		return errors.New("fail to populate institution options. admin_metadata.institution does not exist in the list of registrationFields")
	}

	if param.Registry_InstitutionsUrl.GetString() != "" {
		// Read from Registry.Institutions if Registry.InstitutionsUrl is empty
		// or Registry.Institutions and Registry.InstitutionsUrl are both set
		if len(institutions) > 0 {
			log.Warning("Registry.Institutions and Registry.InstitutionsUrl are both set. Registry.InstitutionsUrl is ignored")
			if isUnique, err := checkUniqueOptions(institutions); !isUnique {
				return errors.Wrap(err, "Institution options from the config are not unique")
			}
			// return here so that we don't init the institution url cache
			return nil
		}

		// Populate optionsUrl for institution field in registrationFields
		registrationFields[instRegIdx].OptionsUrl = param.Registry_InstitutionsUrl.GetString()

		instCacheTTL := param.Registry_InstitutionsUrlReloadMinutes.GetDuration()
		institutions, err := getCachedOptions(param.Registry_InstitutionsUrl.GetString(), instCacheTTL)
		if err != nil {
			return err
		}

		registrationFields[instRegIdx].Options = institutions
	}

	if isUnique, err := checkUniqueOptions(institutions); !isUnique {
		return errors.Wrap(err, "Institution options read from the config are not unique")
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
			if len(conf.Options) == 0 && conf.OptionsUrl == "" {
				return errors.New(fmt.Sprintf("Bad custom registration field, 'enum' type field does not have options or optionsUrl set: %q", conf.Name))
			}
		}
	}

	additionalRegFields := convertCustomRegFields(configFields)
	registrationFields = append(registrationFields, additionalRegFields...)

	return nil
}
