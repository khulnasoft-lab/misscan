package github

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Action struct {
	Metadata           misscanTypes.Metadata
	EnvironmentSecrets []EnvironmentSecret
}

type EnvironmentSecret struct {
	Metadata       misscanTypes.Metadata
	Repository     misscanTypes.StringValue
	Environment    misscanTypes.StringValue
	SecretName     misscanTypes.StringValue
	PlainTextValue misscanTypes.StringValue
	EncryptedValue misscanTypes.StringValue
}
