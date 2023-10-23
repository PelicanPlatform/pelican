package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetHealthStatus(t *testing.T) {
	type mock struct {
		Name       string
		Status     int
		Message    string
		LastUpdate time.Time
	}
	mockData := []mock{
		{
			Name:       "xrootd",
			Status:     1,
			Message:    "Error message",
			LastUpdate: time.Now(),
		},
		{
			Name:       "federation",
			Status:     3,
			Message:    "",
			LastUpdate: time.Now(),
		},
		{
			Name:       "director",
			Status:     2,
			Message:    "",
			LastUpdate: time.Now(),
		},
	}

	setup := func() {
		for _, data := range mockData {
			healthStatus.Store(data.Name, componentStatusInternal{data.Status, data.Message, data.LastUpdate})
		}

	}

	teardown := func() {
		healthStatus.Range(func(key interface{}, value interface{}) bool {
			healthStatus.Delete(key)
			return true
		})
	}

	containsName := func(mockData []mock, name string) bool {
		for _, mockElement := range mockData {
			if mockElement.Name == name {
				return true
			}
		}
		return false
	}

	t.Run("empty-map-returns-empty-list", func(t *testing.T) {
		// clear the map first
		teardown()
		result := GetHealthStatus()
		assert.Equal(t, len(result.ComponentStatus), 0, "Empty health map returns non-empty array")
		assert.Equal(t, result.OverallStatus, "unknown", "Empty health map returns overall status that is not \"unknown\"")
	})
	t.Run("populated-map-works-as-expected", func(t *testing.T) {
		setup()
		defer teardown()
		result := GetHealthStatus()
		assert.Equal(t, len(result.ComponentStatus), len(mockData), "Health map returns array that has different size as expected")
		assert.Equal(t, result.OverallStatus, "critical", "Overall status didn't reflect the worst component health status")
		for _, ele := range result.ComponentStatus {
			assert.True(t, containsName(mockData, ele.Name), "Returned value doesn't exist in map")
		}
	})

}
