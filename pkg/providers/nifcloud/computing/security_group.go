package computing

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SecurityGroup struct {
	Metadata     misscanTypes.Metadata
	Description  misscanTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata    misscanTypes.Metadata
	Description misscanTypes.StringValue
	CIDR        misscanTypes.StringValue
}
