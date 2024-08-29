package server_structs

import (
	"encoding/xml"
)

type (
	TopoServer struct {
		AuthEndpoint string `json:"auth_endpoint"`
		Endpoint     string `json:"endpoint"`
		Resource     string `json:"resource"`
	}

	TopoScitokens struct {
		BasePath   []string `json:"base_path"`
		Issuer     string   `json:"issuer"`
		Restricted []string `json:"restricted_path"`
	}

	TopoCredentialGeneration struct {
		BasePath      string `json:"base_path"`
		Issuer        string `json:"issuer"`
		MaxScopeDepth int    `json:"max_scope_depth"`
		Strategy      string `json:"strategy"`
		VaultIssuer   string `json:"vault_issuer"`
		VaultServer   string `json:"vault_server"`
	}

	TopoNamespace struct {
		Caches               []TopoServer             `json:"caches"`
		Origins              []TopoServer             `json:"origins"`
		CredentialGeneration TopoCredentialGeneration `json:"credential_generation"`
		DirlistHost          string                   `json:"dirlisthost"`
		Path                 string                   `json:"path"`
		ReadHTTPS            bool                     `json:"readhttps"`
		Scitokens            []TopoScitokens          `json:"scitokens"`
		UseTokenOnRead       bool                     `json:"usetokenonread"`
		WritebackHost        string                   `json:"writebackhost"`
	}

	TopologyNamespacesJSON struct {
		Caches     []TopoServer    `json:"caches"`
		Namespaces []TopoNamespace `json:"namespaces"`
	}

	// Structs for encoding downtimes

	TopoResourceGroup struct {
		GroupName string `xml:"GroupName"`
		GroupID   int    `xml:"GroupID"`
	}

	TopoServices struct {
		Service []TopoService `xml:"Service"`
	}

	TopoService struct {
		ID          int    `xml:"ID"`
		Name        string `xml:"Name"`
		Description string `xml:"Description"`
	}

	TopoDowntimeInfo struct {
		XMLName          xml.Name             `xml:"Downtimes"`
		CurrentDowntimes TopoCurrentDowntimes `xml:"CurrentDowntimes"`
	}

	TopoCurrentDowntimes struct {
		Downtimes []TopoServerDowntime `xml:"Downtime"`
	}

	TopoServerDowntime struct {
		ID            int               `xml:"ID"`
		ResourceGroup TopoResourceGroup `xml:"ResourceGroup"`
		ResourceName  string            `xml:"ResourceName"`
		ResourceFQDN  string            `xml:"ResourceFQDN"`
		StartTime     string            `xml:"StartTime"`
		EndTime       string            `xml:"EndTime"`
		CreatedTime   string            `xml:"CreatedTime"`
		UpdateTime    string            `xml:"UpdateTime"`
		Services      TopoServices      `xml:"Services"`
		Description   string            `xml:"Description"`
	}
)
