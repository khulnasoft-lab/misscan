package s3

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type PublicAccessBlock struct {
	Metadata              misscanTypes.Metadata
	BlockPublicACLs       misscanTypes.BoolValue
	BlockPublicPolicy     misscanTypes.BoolValue
	IgnorePublicACLs      misscanTypes.BoolValue
	RestrictPublicBuckets misscanTypes.BoolValue
}

func NewPublicAccessBlock(metadata misscanTypes.Metadata) PublicAccessBlock {
	return PublicAccessBlock{
		Metadata:              metadata,
		BlockPublicPolicy:     misscanTypes.BoolDefault(false, metadata),
		BlockPublicACLs:       misscanTypes.BoolDefault(false, metadata),
		IgnorePublicACLs:      misscanTypes.BoolDefault(false, metadata),
		RestrictPublicBuckets: misscanTypes.BoolDefault(false, metadata),
	}
}
