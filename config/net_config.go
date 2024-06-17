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
	"net"
	"net/url"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

func UpdateConfigFromListener(ln net.Listener) {
	// If we allow net.Listen to select a random open port, we should update the
	// configuration with its value.
	if param.Server_WebPort.GetInt() == 0 {
		addr := ln.Addr()
		tcpAddr, ok := addr.(*net.TCPAddr)
		if ok {
			viper.Set("Server.WebPort", tcpAddr.Port)
			serverUrlStr := param.Server_ExternalWebUrl.GetString()
			serverUrl, err := url.Parse(serverUrlStr)
			if err == nil {
				newUrlStr := "https://" + serverUrl.Hostname() + ":" + strconv.Itoa(tcpAddr.Port)
				viper.Set("Server.WebHost", serverUrl.Hostname())
				viper.Set("Server.ExternalWebUrl", newUrlStr)
				if viper.GetString("Federation.DirectorUrl") == serverUrlStr {
					viper.Set("Federation.DirectorUrl", newUrlStr)
				}
				if viper.GetString("Federation.RegistryUrl") == serverUrlStr {
					viper.Set("Federation.RegistryUrl", newUrlStr)
				}
				fedDiscoveryOnce = &sync.Once{}
				log.Debugln("Random web port used; updated external web URL to", param.Server_ExternalWebUrl.GetString())
			} else {
				log.Errorln("Unable to update external web URL for random port; unable to parse existing URL:", serverUrlStr)
			}
		} else {
			log.Error("Unable to determine TCP address of runtime engine")
		}
	}
}
