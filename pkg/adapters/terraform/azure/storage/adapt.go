package storage

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/storage"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

const minimumTlsVersionOneTwo = "TLS1_2"

func Adapt(modules terraform.Modules) storage.Storage {
	accounts, containers, networkRules := adaptAccounts(modules)

	orphanAccount := storage.Account{
		Metadata:     misscanTypes.NewUnmanagedMetadata(),
		NetworkRules: adaptOrphanNetworkRules(modules, networkRules),
		EnforceHTTPS: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		Containers:   adaptOrphanContainers(modules, containers),
		QueueProperties: storage.QueueProperties{
			Metadata:      misscanTypes.NewUnmanagedMetadata(),
			EnableLogging: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
		},
		MinimumTLSVersion: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
	}

	accounts = append(accounts, orphanAccount)

	return storage.Storage{
		Accounts: accounts,
	}
}

func adaptOrphanContainers(modules terraform.Modules, containers []string) (orphans []storage.Container) {
	accountedFor := make(map[string]bool)
	for _, container := range containers {
		accountedFor[container] = true
	}
	for _, module := range modules {
		for _, containerResource := range module.GetResourcesByType("azurerm_storage_container") {
			if _, ok := accountedFor[containerResource.ID()]; ok {
				continue
			}
			orphans = append(orphans, adaptContainer(containerResource))
		}
	}

	return orphans
}

func adaptOrphanNetworkRules(modules terraform.Modules, networkRules []string) (orphans []storage.NetworkRule) {
	accountedFor := make(map[string]bool)
	for _, networkRule := range networkRules {
		accountedFor[networkRule] = true
	}

	for _, module := range modules {
		for _, networkRuleResource := range module.GetResourcesByType("azurerm_storage_account_network_rules") {
			if _, ok := accountedFor[networkRuleResource.ID()]; ok {
				continue
			}

			orphans = append(orphans, adaptNetworkRule(networkRuleResource))
		}
	}

	return orphans
}

func adaptAccounts(modules terraform.Modules) ([]storage.Account, []string, []string) {
	var accounts []storage.Account
	var accountedForContainers []string
	var accountedForNetworkRules []string

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_storage_account") {
			account := adaptAccount(resource)
			containerResource := module.GetReferencingResources(resource, "azurerm_storage_container", "storage_account_name")
			for _, containerBlock := range containerResource {
				accountedForContainers = append(accountedForContainers, containerBlock.ID())
				account.Containers = append(account.Containers, adaptContainer(containerBlock))
			}
			networkRulesResource := module.GetReferencingResources(resource, "azurerm_storage_account_network_rules", "storage_account_name")
			for _, networkRuleBlock := range networkRulesResource {
				accountedForNetworkRules = append(accountedForNetworkRules, networkRuleBlock.ID())
				account.NetworkRules = append(account.NetworkRules, adaptNetworkRule(networkRuleBlock))
			}
			for _, queueBlock := range module.GetReferencingResources(resource, "azurerm_storage_queue", "storage_account_name") {
				queue := storage.Queue{
					Metadata: queueBlock.GetMetadata(),
					Name:     queueBlock.GetAttribute("name").AsStringValueOrDefault("", queueBlock),
				}
				account.Queues = append(account.Queues, queue)
			}
			accounts = append(accounts, account)
		}
	}

	return accounts, accountedForContainers, accountedForNetworkRules
}

func adaptAccount(resource *terraform.Block) storage.Account {
	account := storage.Account{
		Metadata:     resource.GetMetadata(),
		NetworkRules: nil,
		EnforceHTTPS: misscanTypes.BoolDefault(true, resource.GetMetadata()),
		Containers:   nil,
		QueueProperties: storage.QueueProperties{
			Metadata:      resource.GetMetadata(),
			EnableLogging: misscanTypes.BoolDefault(false, resource.GetMetadata()),
		},
		MinimumTLSVersion:   misscanTypes.StringDefault(minimumTlsVersionOneTwo, resource.GetMetadata()),
		PublicNetworkAccess: resource.GetAttribute("public_network_access_enabled").AsBoolValueOrDefault(true, resource),
	}

	networkRulesBlocks := resource.GetBlocks("network_rules")
	for _, networkBlock := range networkRulesBlocks {
		account.NetworkRules = append(account.NetworkRules, adaptNetworkRule(networkBlock))
	}

	httpsOnlyAttr := resource.GetAttribute("enable_https_traffic_only")
	account.EnforceHTTPS = httpsOnlyAttr.AsBoolValueOrDefault(true, resource)

	queuePropertiesBlock := resource.GetBlock("queue_properties")
	if queuePropertiesBlock.IsNotNil() {
		account.QueueProperties.Metadata = queuePropertiesBlock.GetMetadata()
		loggingBlock := queuePropertiesBlock.GetBlock("logging")
		if loggingBlock.IsNotNil() {
			account.QueueProperties.EnableLogging = misscanTypes.Bool(true, loggingBlock.GetMetadata())
		}
	}

	minTLSVersionAttr := resource.GetAttribute("min_tls_version")
	account.MinimumTLSVersion = minTLSVersionAttr.AsStringValueOrDefault(minimumTlsVersionOneTwo, resource)
	return account
}

func adaptContainer(resource *terraform.Block) storage.Container {
	accessTypeAttr := resource.GetAttribute("container_access_type")
	publicAccess := misscanTypes.StringDefault(storage.PublicAccessOff, resource.GetMetadata())

	if accessTypeAttr.Equals("blob") {
		publicAccess = misscanTypes.String(storage.PublicAccessBlob, accessTypeAttr.GetMetadata())
	} else if accessTypeAttr.Equals("container") {
		publicAccess = misscanTypes.String(storage.PublicAccessContainer, accessTypeAttr.GetMetadata())
	}

	return storage.Container{
		Metadata:     resource.GetMetadata(),
		PublicAccess: publicAccess,
	}
}

func adaptNetworkRule(resource *terraform.Block) storage.NetworkRule {
	var allowByDefault misscanTypes.BoolValue
	var bypass []misscanTypes.StringValue

	defaultActionAttr := resource.GetAttribute("default_action")

	if defaultActionAttr.IsNotNil() {
		allowByDefault = misscanTypes.Bool(defaultActionAttr.Equals("Allow", terraform.IgnoreCase), defaultActionAttr.GetMetadata())
	} else {
		allowByDefault = misscanTypes.BoolDefault(false, resource.GetMetadata())
	}

	if bypassAttr := resource.GetAttribute("bypass"); bypassAttr.IsNotNil() {
		bypass = bypassAttr.AsStringValues()
	}

	return storage.NetworkRule{
		Metadata:       resource.GetMetadata(),
		Bypass:         bypass,
		AllowByDefault: allowByDefault,
	}
}
