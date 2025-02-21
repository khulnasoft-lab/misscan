package container

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Container struct {
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	Metadata                    misscanTypes.Metadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        misscanTypes.BoolValue
	APIServerAuthorizedIPRanges []misscanTypes.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type AddonProfile struct {
	Metadata misscanTypes.Metadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type NetworkProfile struct {
	Metadata      misscanTypes.Metadata
	NetworkPolicy misscanTypes.StringValue // "", "calico", "azure"
}
