package broker

import (
	"context"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/web_ui"
)

var callbackRegistered sync.Once

// InitializeBrokerClient sets up everything needed for a service to use
// brokered connections (as the initiator, not as the broker itself).
func InitializeBrokerClient(ctx context.Context, egrp *errgroup.Group, router *gin.Engine) {
	callbackRegistered.Do(func() {
		RegisterBrokerCallback(ctx, router.Group("/", web_ui.ServerHeaderMiddleware))
	})
	LaunchNamespaceKeyMaintenance(ctx, egrp)
}
