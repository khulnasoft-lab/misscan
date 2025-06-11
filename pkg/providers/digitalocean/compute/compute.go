package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Compute struct {
	Firewalls          []Firewall
	LoadBalancers      []LoadBalancer
	Droplets           []Droplet
	KubernetesClusters []KubernetesCluster
}

type Firewall struct {
	Metadata      misscanTypes.Metadata
	OutboundRules []OutboundFirewallRule
	InboundRules  []InboundFirewallRule
}

type KubernetesCluster struct {
	Metadata     misscanTypes.Metadata
	SurgeUpgrade misscanTypes.BoolValue
	AutoUpgrade  misscanTypes.BoolValue
}

type LoadBalancer struct {
	Metadata            misscanTypes.Metadata
	ForwardingRules     []ForwardingRule
	RedirectHttpToHttps misscanTypes.BoolValue
}

type ForwardingRule struct {
	Metadata      misscanTypes.Metadata
	EntryProtocol misscanTypes.StringValue
}

type OutboundFirewallRule struct {
	Metadata             misscanTypes.Metadata
	DestinationAddresses []misscanTypes.StringValue
}

type InboundFirewallRule struct {
	Metadata        misscanTypes.Metadata
	SourceAddresses []misscanTypes.StringValue
}

type Droplet struct {
	Metadata misscanTypes.Metadata
	SSHKeys  []misscanTypes.StringValue
}
