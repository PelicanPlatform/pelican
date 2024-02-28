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
	"net/url"

	"github.com/pelicanplatform/pelican/common"
)

func convertNamespaceAdsV2ToV1(nsV2 []common.NamespaceAdV2) []common.NamespaceAdV1 {
	// Converts a list of V2 namespace ads to a list of V1 namespace ads.
	// This is for backwards compatibility in the case an old version of a client calls
	// out to a newer verion of the director
	nsV1 := []common.NamespaceAdV1{}

	for _, nsAd := range nsV2 {
		if len(nsAd.Issuer) != 0 {
			for _, iss := range nsAd.Issuer {
				for _, bp := range iss.BasePaths {
					v1Ad := common.NamespaceAdV1{
						Path:          nsAd.Path,
						RequireToken:  !nsAd.Caps.PublicRead,
						Issuer:        iss.IssuerUrl,
						BasePath:      bp,
						Strategy:      nsAd.Generation[0].Strategy,
						VaultServer:   nsAd.Generation[0].VaultServer,
						MaxScopeDepth: nsAd.Generation[0].MaxScopeDepth,
					}
					nsV1 = append(nsV1, v1Ad)
				}
			}
		} else {
			v1Ad := common.NamespaceAdV1{
				Path:         nsAd.Path,
				RequireToken: false,
			}
			nsV1 = append(nsV1, v1Ad)
		}
	}

	return nsV1
}

func ConvertNamespaceAdsV1ToV2(nsAdsV1 []common.NamespaceAdV1, oAd *common.OriginAdvertiseV1) []common.NamespaceAdV2 {
	//Convert a list of V1 namespace ads to a list of V2 namespace ads, note that this
	//isn't the most efficient way of doing so (an interative search as opposed to some sort
	//of index or hash based search)

	var wr bool
	var fallback bool
	var credurl url.URL

	if oAd != nil {
		fallback = oAd.EnableFallbackRead
		wr = oAd.EnableWrite
	} else {
		fallback = true
		wr = false
	}
	nsAdsV2 := []common.NamespaceAdV2{}
	for _, nsAd := range nsAdsV1 {
		nsFound := false
		for i := range nsAdsV2 {
			//Namespace exists, so check if issuer already exists
			if nsAdsV2[i].Path == nsAd.Path {
				nsFound = true
				issFound := false
				tokIssuers := nsAdsV2[i].Issuer
				for j := range tokIssuers {
					//Issuer exists, so add the basepaths to the list
					if tokIssuers[j].IssuerUrl == nsAd.Issuer {
						issFound = true
						bps := tokIssuers[j].BasePaths
						bps = append(bps, nsAd.BasePath)
						tokIss := &nsAdsV2[i].Issuer[j]
						(*tokIss).BasePaths = bps
						break
					}
				}
				//Issuer doesn't exist for the URL, so create a new one
				if nsAd.RequireToken {
					if !issFound {
						if oAd != nil {
							urlPtr, err := url.Parse(oAd.URL)
							if err != nil {
								credurl = nsAd.Issuer
							} else {
								credurl = *urlPtr
							}
						} else {
							credurl = nsAd.Issuer
						}

						tIss := common.TokenIssuer{
							BasePaths:       []string{nsAd.BasePath},
							RestrictedPaths: []string{},
							IssuerUrl:       nsAd.Issuer,
						}
						v2NS := &nsAdsV2[i]
						tis := append(nsAdsV2[i].Issuer, tIss)
						(*v2NS).Issuer = tis
						if len(nsAdsV2[i].Generation) == 0 {
							tGen := common.TokenGen{
								Strategy:         nsAd.Strategy,
								VaultServer:      nsAd.VaultServer,
								MaxScopeDepth:    nsAd.MaxScopeDepth,
								CredentialIssuer: credurl,
							}
							(*v2NS).Generation = []common.TokenGen{tGen}
						}
					}
				}
			}
			break
		}
		//Namespace doesn't exist for the Path, so create a new one
		if !nsFound {
			if oAd != nil {
				urlPtr, err := url.Parse(oAd.URL)
				if err != nil {
					credurl = nsAd.Issuer
				} else {
					credurl = *urlPtr
				}
			} else {
				credurl = nsAd.Issuer
			}

			caps := common.Capabilities{
				PublicRead:   !nsAd.RequireToken,
				Read:         true,
				Write:        wr,
				Listing:      true,
				FallBackRead: fallback,
			}

			newNS := common.NamespaceAdV2{
				PublicRead: !nsAd.RequireToken,
				Caps:       caps,
				Path:       nsAd.Path,
			}

			if nsAd.RequireToken {
				tGen := []common.TokenGen{{
					Strategy:         nsAd.Strategy,
					VaultServer:      nsAd.VaultServer,
					MaxScopeDepth:    nsAd.MaxScopeDepth,
					CredentialIssuer: credurl,
				}}
				tIss := []common.TokenIssuer{{
					BasePaths:       []string{nsAd.BasePath},
					RestrictedPaths: []string{},
					IssuerUrl:       nsAd.Issuer,
				}}

				newNS.Generation = tGen
				newNS.Issuer = tIss
			}

			nsAdsV2 = append(nsAdsV2, newNS)
		}
	}
	return nsAdsV2
}

func convertOriginAd(oAd1 common.OriginAdvertiseV1) common.OriginAdvertiseV2 {
	// Converts a V1 origin ad ot a V2 origin ad
	nsAdsV2 := ConvertNamespaceAdsV1ToV2(oAd1.Namespaces, &oAd1)
	tokIssuers := []common.TokenIssuer{}

	for _, v2Ad := range nsAdsV2 {
		tokIssuers = append(tokIssuers, v2Ad.Issuer...)
	}

	//Origin Capabilities may be different from Namespace Capabilities, but since the original
	//origin didn't contain capabilities, these are currently the defaults - we might want to potentially
	//change this in the future
	caps := common.Capabilities{
		PublicRead:   true,
		Read:         true,
		Write:        oAd1.EnableWrite,
		Listing:      true,
		FallBackRead: oAd1.EnableFallbackRead,
	}

	oAd2 := common.OriginAdvertiseV2{
		Name:       oAd1.Name,
		DataURL:    oAd1.URL,
		WebURL:     oAd1.WebURL,
		Caps:       caps,
		Namespaces: nsAdsV2,
		Issuer:     tokIssuers,
	}
	return oAd2
}
