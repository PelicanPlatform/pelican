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

package server_utils

import (
	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
)

type (
	XRootDServer interface {
		GetServerType() config.ServerType
		SetNamespaceAds([]common.NamespaceAdV2)
		GetNamespaceAds() []common.NamespaceAdV2
		CreateAdvertisement(name string, serverUrl string, serverWebUrl string) (common.OriginAdvertiseV2, error)
		GetNamespaceAdsFromDirector() error
	}

	NamespaceHolder struct {
		namespaceAds []common.NamespaceAdV2
	}
)

func (ns *NamespaceHolder) SetNamespaceAds(ads []common.NamespaceAdV2) {
	ns.namespaceAds = ads
}

func (ns *NamespaceHolder) GetNamespaceAds() []common.NamespaceAdV2 {
	return ns.namespaceAds
}
