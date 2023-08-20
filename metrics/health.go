
package metrics

import (
	"fmt"
	"sync"
)

type (

	ComponentStatus struct {
		Status string `json:"status"`
		Message string `json:"message,omitempty"`
	}

	componentStatusInternal struct {
		Status int
		Message string
	}

	HealthStatus struct {
		OverallStatus string `json:"status"`
		ComponentStatus map[string]ComponentStatus `json:"components"`
	}

)

var (
	healthStatus = sync.Map{}
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
	healthStatus.Store(name, componentStatusInternal{statusInt, msg})
	return nil
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
		}
		if componentStatus.Status < overallStatus {
			overallStatus = componentStatus.Status
		}
		return true
	})
	status.OverallStatus = intToStatus(overallStatus)
	return status
}
