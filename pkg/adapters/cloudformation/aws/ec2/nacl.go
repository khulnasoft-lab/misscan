package ec2

import (
	"strconv"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/cftypes"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func getNetworkACLs(ctx parser.FileContext) (acls []ec2.NetworkACL) {
	for _, aclResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAcl") {
		acl := ec2.NetworkACL{
			Metadata:      aclResource.Metadata(),
			Rules:         getRules(aclResource.ID(), ctx),
			IsDefaultRule: misscanTypes.BoolDefault(false, aclResource.Metadata()),
		}
		acls = append(acls, acl)
	}
	return acls
}

func getRules(id string, ctx parser.FileContext) (rules []ec2.NetworkACLRule) {
	for _, ruleResource := range ctx.GetResourcesByType("AWS::EC2::NetworkAclEntry") {
		aclID := ruleResource.GetProperty("NetworkAclId")
		if aclID.IsString() && aclID.AsString() == id {

			rule := ec2.NetworkACLRule{
				Metadata: ruleResource.Metadata(),
				Type:     misscanTypes.StringDefault(ec2.TypeIngress, ruleResource.Metadata()),
				Action:   misscanTypes.StringDefault(ec2.ActionAllow, ruleResource.Metadata()),
				FromPort: misscanTypes.IntDefault(-1, ruleResource.Metadata()),
				ToPort:   misscanTypes.IntDefault(-1, ruleResource.Metadata()),
				CIDRs:    nil,
			}

			if egressProperty := ruleResource.GetProperty("Egress"); egressProperty.IsBool() {
				if egressProperty.AsBool() {
					rule.Type = misscanTypes.String(ec2.TypeEgress, egressProperty.Metadata())
				} else {
					rule.Type = misscanTypes.String(ec2.TypeIngress, egressProperty.Metadata())
				}
			}

			if actionProperty := ruleResource.GetProperty("RuleAction"); actionProperty.IsString() {
				if actionProperty.AsString() == ec2.ActionAllow {
					rule.Action = misscanTypes.String(ec2.ActionAllow, actionProperty.Metadata())
				} else {
					rule.Action = misscanTypes.String(ec2.ActionDeny, actionProperty.Metadata())
				}
			}

			if protocolProperty := ruleResource.GetProperty("Protocol"); protocolProperty.IsInt() {
				protocol := protocolProperty.AsIntValue().Value()
				rule.Protocol = misscanTypes.String(strconv.Itoa(protocol), protocolProperty.Metadata())
			}

			if ipv4Cidr := ruleResource.GetProperty("CidrBlock"); ipv4Cidr.IsString() {
				rule.CIDRs = append(rule.CIDRs, ipv4Cidr.AsStringValue())
			}

			if ipv6Cidr := ruleResource.GetProperty("Ipv6CidrBlock"); ipv6Cidr.IsString() {
				rule.CIDRs = append(rule.CIDRs, ipv6Cidr.AsStringValue())
			}

			portRange := ruleResource.GetProperty("PortRange")
			fromPort := portRange.GetProperty("From").ConvertTo(cftypes.Int)
			if fromPort.IsInt() {
				rule.FromPort = fromPort.AsIntValue()
			}

			toPort := portRange.GetProperty("To").ConvertTo(cftypes.Int)
			if toPort.IsInt() {
				rule.ToPort = toPort.AsIntValue()
			}

			rules = append(rules, rule)
		}
	}
	return rules
}
