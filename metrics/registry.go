package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var PelicanRegistryFederationNamespaces = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "pelican_registry_federation_namespaces",
	Help: "The number of namespaces in a federation",
}, []string{"status"})
