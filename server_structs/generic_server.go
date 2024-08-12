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
	"strings"
)

type (
	ServerType int // ServerType is a bit mask indicating which Pelican server(s) are running in the current process
)

const (
	CacheType ServerType = 1 << iota
	OriginType
	DirectorType
	RegistryType
	BrokerType
	LocalCacheType
)

// Set sets a list of newServers to ServerType instance
func (sType *ServerType) SetList(newServers []ServerType) {
	for _, server := range newServers {
		*sType |= server
	}
}

// Enable a single server type in the bitmask
func (sType *ServerType) Set(server ServerType) ServerType {
	*sType |= server
	return *sType
}

// IsEnabled checks if a testServer is in the ServerType instance
func (sType ServerType) IsEnabled(testServer ServerType) bool {
	return sType&testServer == testServer
}

// Clear all values in a server type
func (sType *ServerType) Clear() {
	*sType = ServerType(0)
}

// Create a new, empty ServerType bitmask
func NewServerType() ServerType {
	return ServerType(0)
}

// Get the string representation of a ServerType instance. This is intended
// for getting the string form of a single ServerType contant, such as CacheType
// OriginType, etc. To get a string slice of enabled servers, use EnabledServerString()
func (sType ServerType) String() string {
	switch sType {
	case CacheType:
		return "Cache"
	case LocalCacheType:
		return "LocalCache"
	case OriginType:
		return "Origin"
	case DirectorType:
		return "Director"
	case RegistryType:
		return "Registry"
	case BrokerType:
		return "Broker"
	}
	return "Unknown"
}

func (sType *ServerType) SetString(name string) bool {
	switch strings.ToLower(name) {
	case "cache":
		*sType |= CacheType
		return true
	case "localcache":
		*sType |= LocalCacheType
		return true
	case "origin":
		*sType |= OriginType
		return true
	case "director":
		*sType |= DirectorType
		return true
	case "registry":
		*sType |= RegistryType
		return true
	case "broker":
		*sType |= BrokerType
		return true
	}
	return false
}
