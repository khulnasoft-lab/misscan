package keyvault

import (
	"time"

	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/keyvault"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) keyvault.KeyVault {
	adapter := adapter{
		vaultSecretIDs: modules.GetChildResourceIDMapByType("azurerm_key_vault_secret"),
		vaultKeyIDs:    modules.GetChildResourceIDMapByType("azurerm_key_vault_key"),
	}

	return keyvault.KeyVault{
		Vaults: adapter.adaptVaults(modules),
	}
}

type adapter struct {
	vaultSecretIDs terraform.ResourceIDResolutions
	vaultKeyIDs    terraform.ResourceIDResolutions
}

func (a *adapter) adaptVaults(modules terraform.Modules) []keyvault.Vault {

	var vaults []keyvault.Vault
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_key_vault") {
			vaults = append(vaults, a.adaptVault(resource, module))

		}
	}

	orphanResources := modules.GetResourceByIDs(a.vaultSecretIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := keyvault.Vault{
			Metadata:                misscanTypes.NewUnmanagedMetadata(),
			Secrets:                 nil,
			Keys:                    nil,
			EnablePurgeProtection:   misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			SoftDeleteRetentionDays: misscanTypes.IntDefault(0, misscanTypes.NewUnmanagedMetadata()),
			NetworkACLs: keyvault.NetworkACLs{
				Metadata:      misscanTypes.NewUnmanagedMetadata(),
				DefaultAction: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			},
		}
		for _, secretResource := range orphanResources {
			orphanage.Secrets = append(orphanage.Secrets, adaptSecret(secretResource))
		}
		vaults = append(vaults, orphanage)
	}

	orphanResources = modules.GetResourceByIDs(a.vaultKeyIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := keyvault.Vault{
			Metadata:                misscanTypes.NewUnmanagedMetadata(),
			Secrets:                 nil,
			Keys:                    nil,
			EnablePurgeProtection:   misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
			SoftDeleteRetentionDays: misscanTypes.IntDefault(0, misscanTypes.NewUnmanagedMetadata()),
			NetworkACLs: keyvault.NetworkACLs{
				Metadata:      misscanTypes.NewUnmanagedMetadata(),
				DefaultAction: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			},
		}
		for _, secretResource := range orphanResources {
			orphanage.Keys = append(orphanage.Keys, adaptKey(secretResource))
		}
		vaults = append(vaults, orphanage)
	}

	return vaults
}

func (a *adapter) adaptVault(resource *terraform.Block, module *terraform.Module) keyvault.Vault {
	var keys []keyvault.Key
	var secrets []keyvault.Secret

	defaultActionVal := misscanTypes.StringDefault("", resource.GetMetadata())

	secretBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_secret", "key_vault_id")
	for _, secretBlock := range secretBlocks {
		a.vaultSecretIDs.Resolve(secretBlock.ID())
		secrets = append(secrets, adaptSecret(secretBlock))
	}

	keyBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_key", "key_vault_id")
	for _, keyBlock := range keyBlocks {
		a.vaultKeyIDs.Resolve(keyBlock.ID())
		keys = append(keys, adaptKey(keyBlock))
	}

	purgeProtectionAttr := resource.GetAttribute("purge_protection_enabled")
	purgeProtectionVal := purgeProtectionAttr.AsBoolValueOrDefault(false, resource)

	softDeleteRetentionDaysAttr := resource.GetAttribute("soft_delete_retention_days")
	softDeleteRetentionDaysVal := softDeleteRetentionDaysAttr.AsIntValueOrDefault(0, resource)

	aclMetadata := misscanTypes.NewUnmanagedMetadata()
	if aclBlock := resource.GetBlock("network_acls"); aclBlock.IsNotNil() {
		aclMetadata = aclBlock.GetMetadata()
		defaultActionAttr := aclBlock.GetAttribute("default_action")
		defaultActionVal = defaultActionAttr.AsStringValueOrDefault("", resource.GetBlock("network_acls"))
	}

	return keyvault.Vault{
		Metadata:                resource.GetMetadata(),
		Secrets:                 secrets,
		Keys:                    keys,
		EnablePurgeProtection:   purgeProtectionVal,
		SoftDeleteRetentionDays: softDeleteRetentionDaysVal,
		NetworkACLs: keyvault.NetworkACLs{
			Metadata:      aclMetadata,
			DefaultAction: defaultActionVal,
		},
	}
}

func adaptSecret(resource *terraform.Block) keyvault.Secret {
	contentTypeAttr := resource.GetAttribute("content_type")
	contentTypeVal := contentTypeAttr.AsStringValueOrDefault("", resource)

	return keyvault.Secret{
		Metadata:    resource.GetMetadata(),
		ContentType: contentTypeVal,
		ExpiryDate:  resolveExpiryDate(resource),
	}
}

func adaptKey(resource *terraform.Block) keyvault.Key {

	return keyvault.Key{
		Metadata:   resource.GetMetadata(),
		ExpiryDate: resolveExpiryDate(resource),
	}
}

func resolveExpiryDate(resource *terraform.Block) misscanTypes.TimeValue {
	expiryDateAttr := resource.GetAttribute("expiration_date")
	expiryDateVal := misscanTypes.TimeDefault(time.Time{}, resource.GetMetadata())

	if expiryDateAttr.IsString() {
		expiryDateString := expiryDateAttr.Value().AsString()
		if expiryDate, err := time.Parse(time.RFC3339, expiryDateString); err == nil {
			expiryDateVal = misscanTypes.Time(expiryDate, expiryDateAttr.GetMetadata())
		}
	} else if expiryDateAttr.IsNotNil() {
		expiryDateVal = misscanTypes.TimeUnresolvable(expiryDateAttr.GetMetadata())
	}

	return expiryDateVal
}
