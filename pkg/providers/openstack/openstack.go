package openstack

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type OpenStack struct {
	Compute    Compute
	Networking Networking
}

type Compute struct {
	Instances []Instance
	Firewall  Firewall
}

type Firewall struct {
	AllowRules []FirewallRule
	DenyRules  []FirewallRule
}

type FirewallRule struct {
	Metadata        misscanTypes.Metadata
	Source          misscanTypes.StringValue
	Destination     misscanTypes.StringValue
	SourcePort      misscanTypes.StringValue
	DestinationPort misscanTypes.StringValue
	Enabled         misscanTypes.BoolValue
}

type Instance struct {
	Metadata      misscanTypes.Metadata
	AdminPassword misscanTypes.StringValue
}
