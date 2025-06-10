package database

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/database"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/azure"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func adaptMSSQLServers(deployment azure.Deployment) (msSQlServers []database.MSSQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Sql/servers") {
		msSQlServers = append(msSQlServers, adaptMSSQLServer(resource, deployment))
	}
	return msSQlServers
}

func adaptMSSQLServer(resource azure.Resource, deployment azure.Deployment) database.MSSQLServer {
	return database.MSSQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      resource.Properties.GetMapValue("sslEnforcement").AsBoolValue(false, resource.Metadata),
			MinimumTLSVersion:         resource.Properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled", resource.Metadata),
			EnablePublicNetworkAccess: resource.Properties.GetMapValue("publicNetworkAccess").AsBoolValue(false, resource.Metadata),
			FirewallRules:             addFirewallRule(resource),
		},
		ExtendedAuditingPolicies: adaptExtendedAuditingPolicies(resource, deployment),
		SecurityAlertPolicies:    adaptSecurityAlertPolicies(resource, deployment),
	}
}

func adaptExtendedAuditingPolicies(resource azure.Resource, deployment azure.Deployment) (policies []database.ExtendedAuditingPolicy) {

	for _, policy := range deployment.GetResourcesByType("Microsoft.Sql/servers/extendedAuditingSettings") {
		policies = append(policies, database.ExtendedAuditingPolicy{
			Metadata:        policy.Metadata,
			RetentionInDays: policy.Properties.GetMapValue("retentionDays").AsIntValue(0, policy.Metadata),
		})
	}

	return policies
}

func adaptSecurityAlertPolicies(resource azure.Resource, deployment azure.Deployment) (policies []database.SecurityAlertPolicy) {
	for _, policy := range deployment.GetResourcesByType("Microsoft.Sql/servers/securityAlertPolicies") {
		policies = append(policies, database.SecurityAlertPolicy{
			Metadata:           policy.Metadata,
			EmailAddresses:     adaptStringList(policy.Properties.GetMapValue("emailAddresses")),
			DisabledAlerts:     adaptStringList(policy.Properties.GetMapValue("disabledAlerts")),
			EmailAccountAdmins: policy.Properties.GetMapValue("emailAccountAdmins").AsBoolValue(false, policy.Metadata),
		})
	}
	return policies
}

func adaptStringList(value azure.Value) []misscanTypes.StringValue {
	var list []misscanTypes.StringValue
	for _, v := range value.AsList() {
		list = append(list, v.AsStringValue("", value.Metadata))
	}
	return list
}
