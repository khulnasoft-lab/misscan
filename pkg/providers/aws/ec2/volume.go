package ec2

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Volume struct {
	Metadata   misscanTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	KMSKeyID misscanTypes.StringValue
}
