package registry

import (
	"context"
	"time"

	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func getCountofFederationNamespacesByStatus(status server_structs.RegistrationStatus) (int, error) {
	// filter by approved, denied, pending
	filterNs := server_structs.Registration{
		AdminMetadata: server_structs.AdminMetadata{
			Status: status,
		},
	}

	// prefixForNamespace allows us to get all namespaces that are not prefixed by /origins/ or /caches/
	namespaces, err := getRegistrationsByFilter(filterNs, prefixForNamespace, false)
	if err != nil {
		return 0, err
	}

	return len(namespaces), nil
}

func updateOSDFInstitutionCountMetric() error {
	institutions := []registrationFieldOption{}
	var institutionCount int
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		log.Warning("Failed to update institution count metric: failed to unmarshal institutions.", err.Error())
		return err
	}

	if param.Registry_InstitutionsUrl.GetString() != "" {
		if len(institutions) > 0 {
			institutionCount = len(institutions)
		} else {
			institutions, err := getCachedOptions(param.Registry_InstitutionsUrl.GetString(), ttlcache.DefaultTTL)
			if err != nil {
				log.Warningln("Failed to update institution count metric.", err.Error())
				return err
			}
			institutionCount = len(institutions)
		}
	}

	metrics.PelicanOSDFInstitutions.Set(float64(institutionCount))
	return nil
}

// LaunchInactiveRegistrationCleanup starts a goroutine that periodically finds servers whose
// last_seen (updated on metadata polling) is older than Registry.InactiveRegistrationTimeout,
// deletes all registrations linked to those servers via services, then deletes the server rows.
func LaunchInactiveRegistrationCleanup(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(param.Registry_InactiveRegistrationCleanupInterval.GetDuration())
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				timeout := param.Registry_InactiveRegistrationTimeout.GetDuration()
				cutoff := time.Now().UTC().Add(-timeout)
				nRegs, nServers, err := deleteStaleServerRegistrations(cutoff)
				if err != nil {
					log.Warningf("Failed to clean up stale server registrations: %v", err)
					continue
				}
				if nRegs > 0 || nServers > 0 {
					log.Infof("Inactive registration cleanup: removed %d pending registration(s) across %d server(s) that had no activity for more than %s", nRegs, nServers, timeout)
				}
			}
		}
	})
}

func LaunchRegistryMetrics(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(time.Second * 15)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if config.GetPreferredPrefix() == config.OsdfPrefix {
					if err := updateOSDFInstitutionCountMetric(); err != nil {
						log.Warningln("Failed to update OSDF institution count metric.", err.Error())
						continue
					}
				}

				// get the amount of approved, denied, and pending namespaces
				numApproved, err := getCountofFederationNamespacesByStatus(server_structs.RegApproved)
				if err != nil {
					log.Warningln("Failed to update namespace metric for approved namespaces.", err.Error())
					continue
				}
				metrics.PelicanRegistryFederationNamespaces.WithLabelValues(server_structs.RegApproved.LowerString()).Set(float64(numApproved))

				numDenied, err := getCountofFederationNamespacesByStatus(server_structs.RegDenied)
				if err != nil {
					log.Warningln("Failed to update namespace metric for denied namespaces.", err.Error())
					continue
				}
				metrics.PelicanRegistryFederationNamespaces.WithLabelValues(server_structs.RegDenied.LowerString()).Set(float64(numDenied))

				numPending, err := getCountofFederationNamespacesByStatus(server_structs.RegPending)
				if err != nil {
					log.Warningln("Failed to update namespace metric for pending namespaces.", err.Error())
					continue
				}
				metrics.PelicanRegistryFederationNamespaces.WithLabelValues(server_structs.RegPending.LowerString()).Set(float64(numPending))
			}
		}
	})
}
