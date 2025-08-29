package metrics

import (
	"context"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

// This function should be used up until XRootD v6 is released
// When XRootD v6 is released, these stats will be available over the g-stream
// Until then the stats are consumed from Cache.ClientStatisticsLocation
// When XRootD v6 is released, this function should be removed along with Cache.ClientStatisticsLocation
func LaunchXrdCurlStatsMonitoring(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				stats, err := os.ReadFile(param.Cache_ClientStatisticsLocation.GetString())
				if err != nil {
					log.Errorf("XrdCurlStats monitoring: failed to read stats file: %v", err)
					continue
				}
				err = handleXrdcurlstatsPacket(stats)
				if err != nil {
					log.Errorf("XrdCurlStats monitoring: failed to handle stats: %v", err)
					continue
				}
			}
		}
	})
}
