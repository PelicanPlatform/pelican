package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthStatusString(t *testing.T) {
	expectedStrings := [...]string{"critical", "warning", "ok", "unknown"}

	t.Run("health-status-string-handles-out-of-range-index", func(t *testing.T) {
		invalidIndex := len(expectedStrings) + 1
		for idx := range expectedStrings {
			assert.Equal(t, expectedStrings[idx], HealthStatusEnum(idx+1).String())
		}
		require.Equal(t, statusIndexErrorMessage, HealthStatusEnum(invalidIndex).String())
	})
}
