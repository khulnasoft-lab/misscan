package sns

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SNS struct {
	Topics []Topic
}

type Topic struct {
	Metadata   misscanTypes.Metadata
	ARN        misscanTypes.StringValue
	Encryption Encryption
}

type Encryption struct {
	Metadata misscanTypes.Metadata
	KMSKeyID misscanTypes.StringValue
}
