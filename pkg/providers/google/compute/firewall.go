package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Firewall struct {
	Metadata     misscanTypes.Metadata
	Name         misscanTypes.StringValue
	IngressRules []IngressRule
	EgressRules  []EgressRule
	SourceTags   []misscanTypes.StringValue
	TargetTags   []misscanTypes.StringValue
}

type FirewallRule struct {
	Metadata misscanTypes.Metadata
	Enforced misscanTypes.BoolValue
	IsAllow  misscanTypes.BoolValue
	Protocol misscanTypes.StringValue
	Ports    []PortRange
}

type PortRange struct {
	Metadata misscanTypes.Metadata
	Start    misscanTypes.IntValue
	End      misscanTypes.IntValue
}

type IngressRule struct {
	Metadata misscanTypes.Metadata
	FirewallRule
	SourceRanges []misscanTypes.StringValue
}

type EgressRule struct {
	Metadata misscanTypes.Metadata
	FirewallRule
	DestinationRanges []misscanTypes.StringValue
}
