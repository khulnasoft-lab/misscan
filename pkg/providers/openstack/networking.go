package openstack

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Networking struct {
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	Metadata    misscanTypes.Metadata
	Name        misscanTypes.StringValue
	Description misscanTypes.StringValue
	Rules       []SecurityGroupRule
}

// SecurityGroupRule describes https://registry.terraform.io/providers/terraform-provider-openstack/openstack/latest/docs/resources/networking_secgroup_rule_v2
type SecurityGroupRule struct {
	Metadata  misscanTypes.Metadata
	IsIngress misscanTypes.BoolValue
	EtherType misscanTypes.IntValue    // 4 or 6 for ipv4/ipv6
	Protocol  misscanTypes.StringValue // e.g. tcp
	PortMin   misscanTypes.IntValue
	PortMax   misscanTypes.IntValue
	CIDR      misscanTypes.StringValue
}
