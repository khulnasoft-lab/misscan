package gke

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata                 misscanTypes.Metadata
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           misscanTypes.StringValue
	MonitoringService        misscanTypes.StringValue
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      misscanTypes.BoolValue
	EnableLegacyABAC         misscanTypes.BoolValue
	ResourceLabels           misscanTypes.MapValue
	RemoveDefaultNodePool    misscanTypes.BoolValue
	EnableAutpilot           misscanTypes.BoolValue
	DatapathProvider         misscanTypes.StringValue
}

type NodeConfig struct {
	Metadata               misscanTypes.Metadata
	ImageType              misscanTypes.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         misscanTypes.StringValue
	EnableLegacyEndpoints  misscanTypes.BoolValue
}

type WorkloadMetadataConfig struct {
	Metadata     misscanTypes.Metadata
	NodeMetadata misscanTypes.StringValue
}

type MasterAuth struct {
	Metadata          misscanTypes.Metadata
	ClientCertificate ClientCertificate
	Username          misscanTypes.StringValue
	Password          misscanTypes.StringValue
}

type ClientCertificate struct {
	Metadata         misscanTypes.Metadata
	IssueCertificate misscanTypes.BoolValue
}

type PrivateCluster struct {
	Metadata           misscanTypes.Metadata
	EnablePrivateNodes misscanTypes.BoolValue
}

type NetworkPolicy struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type MasterAuthorizedNetworks struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	CIDRs    []misscanTypes.StringValue
}

type IPAllocationPolicy struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type NodePool struct {
	Metadata   misscanTypes.Metadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	Metadata          misscanTypes.Metadata
	EnableAutoRepair  misscanTypes.BoolValue
	EnableAutoUpgrade misscanTypes.BoolValue
}
