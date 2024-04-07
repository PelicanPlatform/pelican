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

package server_structs

import (
	"github.com/pelicanplatform/pelican/config"
)

type (
	XRootDServer interface {
		GetServerType() config.ServerType
		SetNamespaceAds([]NamespaceAdV2)
		GetNamespaceAds() []NamespaceAdV2
		CreateAdvertisement(name string, serverUrl string, serverWebUrl string) (*OriginAdvertiseV2, error)
		GetNamespaceAdsFromDirector() error

		// Return the PIDs corresponding to the running process(es) for the XRootD
		// server instance (could be multiple if there's both cmsd and xrootd)
		GetPids() []int

		// Set the PIDs associated with the running process(es) for the XRootD instance
		SetPids([]int)
	}

	NamespaceHolder struct {
		namespaceAds []NamespaceAdV2
	}
)

func (ns *NamespaceHolder) SetNamespaceAds(ads []NamespaceAdV2) {
	ns.namespaceAds = ads
}

func (ns *NamespaceHolder) GetNamespaceAds() []NamespaceAdV2 {
	return ns.namespaceAds
}
