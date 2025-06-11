package ec2

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type NetworkACL struct {
	Metadata      misscanTypes.Metadata
	Rules         []NetworkACLRule
	IsDefaultRule misscanTypes.BoolValue
}

type SecurityGroup struct {
	Metadata     misscanTypes.Metadata
	IsDefault    misscanTypes.BoolValue
	Description  misscanTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
	VPCID        misscanTypes.StringValue
}

type SecurityGroupRule struct {
	Metadata    misscanTypes.Metadata
	Description misscanTypes.StringValue
	CIDRs       []misscanTypes.StringValue
	Protocol    misscanTypes.StringValue
	FromPort    misscanTypes.IntValue
	ToPort      misscanTypes.IntValue
}

type VPC struct {
	Metadata        misscanTypes.Metadata
	ID              misscanTypes.StringValue
	IsDefault       misscanTypes.BoolValue
	SecurityGroups  []SecurityGroup
	FlowLogsEnabled misscanTypes.BoolValue
}

const (
	TypeIngress = "ingress"
	TypeEgress  = "egress"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

type NetworkACLRule struct {
	Metadata misscanTypes.Metadata
	Type     misscanTypes.StringValue
	Action   misscanTypes.StringValue
	Protocol misscanTypes.StringValue
	CIDRs    []misscanTypes.StringValue
	FromPort misscanTypes.IntValue
	ToPort   misscanTypes.IntValue
}
