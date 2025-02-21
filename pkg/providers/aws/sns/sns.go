package sns

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SNS struct {
	Topics []Topic
}

func NewTopic(arn string, metadata misscanTypes.Metadata) *Topic {
	return &Topic{
		Metadata: metadata,
		ARN:      misscanTypes.String(arn, metadata),
		Encryption: Encryption{
			Metadata: metadata,
			KMSKeyID: misscanTypes.StringDefault("", metadata),
		},
	}
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
