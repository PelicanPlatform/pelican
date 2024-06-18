package registry

import (
	"context"
	"time"

	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func getCountofFederationNamespacesByStatus(status server_structs.RegistrationStatus) (int, error) {
	// filter by approved, denied, pending
	filterNs := server_structs.Namespace{
		AdminMetadata: server_structs.AdminMetadata{
			Status: status,
		},
	}

	// prefixForNamespace allows us to get all namespaces that are not prefixed by /origins/ or /caches/
	namespaces, err := getNamespacesByFilter(filterNs, prefixForNamespace, false)
	if err != nil {
		return 0, err
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
				return nil
			case <-ticker.C:
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

func LaunchFederationInstitutionMetrics(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(time.Second * 15)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				var institutions interface{}
				if param.Registry_Institutions.IsSet() && param.Registry_InstitutionsUrl.IsSet() {
					institutions = param.Registry_Institutions
				} else if param.Registry_InstitutionsUrl.IsSet() {
					institutions = param.Registry_InstitutionsUrl
				} else if param.Registry_Institutions.IsSet() {
					institutions = param.Registry_Institutions
				} else {
					log.Warning("No institutions specified for federation metrics")
					return nil
				}

				var institutionCount int
				switch institutions := institutions.(type) {
				case param.ObjectParam: // param.Registry_Institutions
					institutionsList := []registrationFieldOption{}
					if err := institutions.Unmarshal(&institutionsList); err != nil {
						log.Warningln("Failed to update institution count metric.", err.Error())
						continue
					}
					institutionCount = len(institutionsList)
				case param.StringParam: // param.Registry_InstitutionsUrl
					url := institutions.GetString()
					if len(url) != 0 {
						log.Warningln("Failed to update institution count metric.")
						continue
					}

					institutionsList, err := getCachedOptions(url, ttlcache.DefaultTTL)
					if err != nil {
						log.Warningln("Failed to update institution count metric.", err.Error())
						continue
					}
					institutionCount = len(institutionsList)
				}

				metrics.PelicanOSDFInstitutions.Set(float64(institutionCount))

			}
		}
	})
}
