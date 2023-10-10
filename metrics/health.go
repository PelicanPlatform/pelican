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
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type (
	ComponentStatus struct {
		Status     string `json:"status"`
		Message    string `json:"message,omitempty"`
		LastUpdate int64  `json:"last_update"`
	}

	componentStatusInternal struct {
		Status     int
		Message    string
		LastUpdate time.Time
	}

	HealthStatus struct {
		OverallStatus   string                     `json:"status"`
		ComponentStatus map[string]ComponentStatus `json:"components"`
	}
)

var (
	healthStatus               = sync.Map{}
	PromHealthStatusLastUpdate = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "last_update_component_health_status",
		Help: "Last update of components health status",
	}, []string{"component", "status", "message"})
)

func statusToInt(status string) (int, error) {
	switch status {
	case "ok":
		return 3, nil
	case "warning":
		return 2, nil
	case "critical":
		return 1, nil
	}
	return 0, fmt.Errorf("Unknown component status: %v", status)
}

func intToStatus(statusInt int) string {
	switch statusInt {
	case 3:
		return "ok"
	case 2:
		return "warning"
	case 1:
		return "critical"
	}
	return "unknown"
}

func SetComponentHealthStatus(name, state, msg string) error {
	statusInt, err := statusToInt(state)
	if err != nil {
		return err
	}
	now := time.Now()
	healthStatus.Store(name, componentStatusInternal{statusInt, msg, now})

	PromHealthStatusLastUpdate.With(
		prometheus.Labels{"component": name, "status": state, "message": msg}).
		Set(float64(now.UnixMicro()))
	return nil
}

func DeleteComponentHealthStatus(name string) {
	healthStatus.Delete(name)
}

func GetHealthStatus() HealthStatus {
	status := HealthStatus{}
	status.OverallStatus = "unknown"
	overallStatus := 4
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
			intToStatus(componentStatus.Status),
			componentStatus.Message,
			componentStatus.LastUpdate.Unix(),
		}
		if componentStatus.Status < overallStatus {
			overallStatus = componentStatus.Status
		}
		return true
	})
	status.OverallStatus = intToStatus(overallStatus)
	return status
}
