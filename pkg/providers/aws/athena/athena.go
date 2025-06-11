package athena

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Athena struct {
	Databases  []Database
	Workgroups []Workgroup
}

type Database struct {
	Metadata   misscanTypes.Metadata
	Name       misscanTypes.StringValue
	Encryption EncryptionConfiguration
}

type Workgroup struct {
	Metadata             misscanTypes.Metadata
	Name                 misscanTypes.StringValue
	Encryption           EncryptionConfiguration
	EnforceConfiguration misscanTypes.BoolValue
}

const (
	EncryptionTypeNone   = ""
	EncryptionTypeSSES3  = "SSE_S3"
	EncryptionTypeSSEKMS = "SSE_KMS"
	EncryptionTypeCSEKMS = "CSE_KMS"
)

type EncryptionConfiguration struct {
	Metadata misscanTypes.Metadata
	Type     misscanTypes.StringValue
}
