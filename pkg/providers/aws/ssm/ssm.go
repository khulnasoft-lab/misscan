package ssm

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	Metadata misscanTypes.Metadata
	KMSKeyID misscanTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/secretsmanager"
