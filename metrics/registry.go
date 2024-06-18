package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var PelicanRegistryFederationNamespaces = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "pelican_registry_federation_namespaces",
	Help: "The number of federation namespace associated with a public key, excluding server namespaces, in the registry.",
}, []string{"status"})

var PelicanOSDFInstitutions = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "pelican_osdf_institution_count",
	Help: "Total number of participating institutions in OSDF mode.",
})
