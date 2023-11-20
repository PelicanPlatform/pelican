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

package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type (
	// This is for API response so we want to display string representation of status
	ComponentStatus struct {
		Status     string `json:"status"`
		Message    string `json:"message,omitempty"`
		LastUpdate int64  `json:"last_update"`
	}

	componentStatusInternal struct {
		Status     HealthStatusEnum
		Message    string
		LastUpdate time.Time
	}

	HealthStatus struct {
		OverallStatus   string                     `json:"status"`
		ComponentStatus map[string]ComponentStatus `json:"components"`
	}

	HealthStatusEnum int

	HealthStatusComponent string
)

const (
	StatusCritical HealthStatusEnum = iota + 1
	StatusWarning
	StatusOK
	StatusUnknown // Do not abuse this enum. Use others when possible
)

const statusIndexErrorMessage = "Error: status string index out of range"

// Naming convention for components:
//
//	ServiceName1Name2_ComponentName
//
// i.e. For ""OriginCache_XRootD", it means this component is available at both
// Origin and Cache. Please come up with the largest possible scope of the component
const (
	OriginCache_XRootD     HealthStatusComponent = "xrootd"
	OriginCache_CMSD       HealthStatusComponent = "cmsd"
	OriginCache_Federation HealthStatusComponent = "federation" // Advertise to the director
	OriginCache_Director   HealthStatusComponent = "director"   // file transfer with director
	// TODO: WebUI health status is only set at origin_serve for now. We will soon
	// move this logic to all server web-ui in issue #308
	Server_WebUI HealthStatusComponent = "web-ui"
)

var (
	healthStatus = sync.Map{}

	PelicanHealthStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_component_health_status",
		Help: "The health status of various components",
	}, []string{"component"})

	PelicanHealthLastUpdate = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_component_health_status_last_update",
		Help: "Last update timestamp of components health status",
	}, []string{"component"})
)

// Unfortunately we don't have a better way to ensure the enum constants always have
// matched string representation, so we will return "Error: status string index out of range"
// as an indicator
func (status HealthStatusEnum) String() string {
	strings := [...]string{"critical", "warning", "ok", "unknown"}

	if int(status) < 1 || int(status) > len(strings) {
		return statusIndexErrorMessage
	}
	return strings[status-1]
}

func (component HealthStatusComponent) String() string {
	return string(component)
}

// Add/update the component health status. If you have a new component to record,
// please go to metrics/health and register your component as a new constant of
// type HealthStatusComponent. Also note that StatusUnknown is mostly for internal
// use only, please try to avoid setting this as your component status
func SetComponentHealthStatus(name HealthStatusComponent, state HealthStatusEnum, msg string) {
	now := time.Now()
	healthStatus.Store(name.String(), componentStatusInternal{state, msg, now})

	PelicanHealthStatus.With(
		prometheus.Labels{"component": name.String()}).
		Set(float64(state))

	PelicanHealthLastUpdate.With(prometheus.Labels{"component": name.String()}).
		SetToCurrentTime()
}

func DeleteComponentHealthStatus(name HealthStatusComponent) {
	healthStatus.Delete(name.String())
}

func GetHealthStatus() HealthStatus {
	status := HealthStatus{}
	status.OverallStatus = StatusUnknown.String()
	overallStatus := StatusUnknown
	healthStatus.Range(func(component, compstat any) bool {
		componentStatus, ok := compstat.(componentStatusInternal)
		if !ok {
			return true
		}
		componentString, ok := component.(string)
		if !ok {
			return true
		}
		if status.ComponentStatus == nil {
			status.ComponentStatus = make(map[string]ComponentStatus)
		}
		status.ComponentStatus[componentString] = ComponentStatus{
			componentStatus.Status.String(),
			componentStatus.Message,
			componentStatus.LastUpdate.Unix(),
		}
		if componentStatus.Status < overallStatus {
			overallStatus = componentStatus.Status
		}
		return true
	})
	status.OverallStatus = overallStatus.String()
	return status
}
