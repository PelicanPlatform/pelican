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
)

// Converts adn sets environment variables with non-Pelican prefixes (i.e. OSDF/STASH) to PELICAN ones
// It will skip the ones that have a PELICAN prefixed env already set
func osdfEnvToPelican() {
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
				osdfKey := strings.SplitN(env, "=", 2)[0]
				pelicanEnv := "PELICAN_" + strings.TrimPrefix(env, prefix.String()+"_")
				pelicanKey := strings.SplitN(pelicanEnv, "=", 2)[0]
				pelicanVal := strings.SplitN(pelicanEnv, "=", 2)[1]
				if os.Getenv(pelicanKey) != "" {
					log.Errorf("Converting environment variable from %s to %s failed. %s already exists.", osdfKey, pelicanKey, pelicanKey)
					continue
				}
				os.Setenv(pelicanKey, pelicanVal)
			}
		}
	}
}
