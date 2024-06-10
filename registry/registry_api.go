package registry

import (
	"context"
	"time"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/server_structs"
	"golang.org/x/sync/errgroup"
)

func getCountofFederationNamespacesByStatus(status server_structs.RegistrationStatus) (int, error) {
	filterNs := server_structs.Namespace{
		AdminMetadata: server_structs.AdminMetadata{
			Status: status,
		},
	}

	namespaces, err := getNamespacesByFilter(filterNs, prefixForNamespace, false)
	if err != nil {
		return 0, nil
	}

	return len(namespaces), nil
}

func LaunchNamespaceMetrics(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(time.Second * 15)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				numApproved, err := getCountofFederationNamespacesByStatus(server_structs.RegApproved)
				if err != nil {
					return err
				}
				metrics.PelicanRegistryFederationNamespaces.WithLabelValues(server_structs.RegApproved.LowerString()).Set(float64(numApproved))

				numDenied, err := getCountofFederationNamespacesByStatus(server_structs.RegDenied)
				if err != nil {
					return err
				}
				metrics.PelicanRegistryFederationNamespaces.WithLabelValues(server_structs.RegDenied.LowerString()).Set(float64(numDenied))

				numPending, err := getCountofFederationNamespacesByStatus(server_structs.RegPending)
				if err != nil {
					return err
				}
				metrics.PelicanRegistryFederationNamespaces.WithLabelValues(server_structs.RegPending.LowerString()).Set(float64(numPending))
			}
		}
	})
}
