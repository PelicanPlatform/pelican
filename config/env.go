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

package config

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Bind environment variables with non-Pelican prefixes (i.e. OSDF/STASH) to correct Pelican config keys
func bindNonPelicanEnv() {
	prefix := GetPreferredPrefix()
	if prefix != PelicanPrefix {
		found := false
		envs := os.Environ()
		for _, env := range envs {
			if strings.HasPrefix(env, prefix.String()+"_") { // OSDF_ | STASH_
				if !found {
					log.Warningf("Environment variables with %s prefix will be deprecated in the next feature release. Please use PELICAN prefix instead.", prefix.String())
					found = true
				}
				osdfKey := strings.SplitN(env, "=", 2)[0]                                                   // OSDF_FOO_BAR
				viperKey := strings.Replace(strings.TrimPrefix(osdfKey, prefix.String()+"_"), "_", ".", -1) // FOO.BAR
				if err := viper.BindEnv(viperKey, osdfKey); err != nil {
					log.Errorf("Error binding environment variable %s to configuration parameter %s: %v", osdfKey, viperKey, err)
				}
			}
		}
	}
}
