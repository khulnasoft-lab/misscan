package rdb

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func adaptDBSecurityGroups(modules terraform.Modules) []rdb.DBSecurityGroup {
	var dbSecurityGroups []rdb.DBSecurityGroup

	for _, resource := range modules.GetResourcesByType("nifcloud_db_security_group") {
		dbSecurityGroups = append(dbSecurityGroups, adaptDBSecurityGroup(resource))
	}
	return dbSecurityGroups
}

func adaptDBSecurityGroup(resource *terraform.Block) rdb.DBSecurityGroup {
	var cidrs []misscanTypes.StringValue

	for _, rule := range resource.GetBlocks("rule") {
		cidrs = append(cidrs, rule.GetAttribute("cidr_ip").AsStringValueOrDefault("", resource))
	}

	return rdb.DBSecurityGroup{
		Metadata:    resource.GetMetadata(),
		Description: resource.GetAttribute("description").AsStringValueOrDefault("", resource),
		CIDRs:       cidrs,
	}
}
