package kubernetes

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Kubernetes struct {
	NetworkPolicies []NetworkPolicy
}

type NetworkPolicy struct {
	Metadata misscanTypes.Metadata
	Spec     NetworkPolicySpec
}

type NetworkPolicySpec struct {
	Metadata misscanTypes.Metadata
	Egress   Egress
	Ingress  Ingress
}

type Egress struct {
	Metadata         misscanTypes.Metadata
	Ports            []Port
	DestinationCIDRs []misscanTypes.StringValue
}

type Ingress struct {
	Metadata    misscanTypes.Metadata
	Ports       []Port
	SourceCIDRs []misscanTypes.StringValue
}

type Port struct {
	Metadata misscanTypes.Metadata
	Number   misscanTypes.StringValue // e.g. "http" or "80"
	Protocol misscanTypes.StringValue
}
