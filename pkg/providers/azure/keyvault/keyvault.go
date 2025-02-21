package keyvault

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type KeyVault struct {
	Vaults []Vault
}

type Vault struct {
	Metadata                misscanTypes.Metadata
	Secrets                 []Secret
	Keys                    []Key
	EnablePurgeProtection   misscanTypes.BoolValue
	SoftDeleteRetentionDays misscanTypes.IntValue
	NetworkACLs             NetworkACLs
}

type NetworkACLs struct {
	Metadata      misscanTypes.Metadata
	DefaultAction misscanTypes.StringValue
}

type Key struct {
	Metadata   misscanTypes.Metadata
	ExpiryDate misscanTypes.TimeValue
}

type Secret struct {
	Metadata    misscanTypes.Metadata
	ContentType misscanTypes.StringValue
	ExpiryDate  misscanTypes.TimeValue
}
