package broker

import (
	"context"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

var callbackRegistered sync.Once

func init() {
	server_utils.RegisterBrokerReset(Reset)
}

// InitializeBrokerClient sets up everything needed for a service to use
// brokered connections (as the initiator, not as the broker itself).
func InitializeBrokerClient(ctx context.Context, egrp *errgroup.Group, router *gin.Engine) {
	callbackRegistered.Do(func() {
		RegisterBrokerCallback(ctx, router.Group("/", web_ui.ServerHeaderMiddleware))
	})
	LaunchNamespaceKeyMaintenance(ctx, egrp)
}

// Reset the global state of the module; it is assumed this is invoked
// from unit tests only without concurrency issues.
func Reset() {
	callbackRegistered = sync.Once{}
	ResetState()
}
