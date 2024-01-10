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

package cache_ui

import (
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/server_utils"
)

type (
	CacheServer struct {
		server_utils.NamespaceHolder
	}
)

func (server *CacheServer) CreateAdvertisement(name string, originUrl string, originWebUrl string) (director.ServerAdvertise, error) {
	ad := director.ServerAdvertise{
		Name:       name,
		URL:        originUrl,
		WebURL:     originWebUrl,
		Namespaces: server.GetNamespaceAds(),
	}

	return ad, nil
}

func (server *CacheServer) GetServerType() config.ServerType {
	return config.CacheType
}
