package s3

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Bucket struct {
	Metadata                      misscanTypes.Metadata
	Name                          misscanTypes.StringValue
	PublicAccessBlock             *PublicAccessBlock
	BucketPolicies                []iam.Policy
	Encryption                    Encryption
	Versioning                    Versioning
	Logging                       Logging
	ACL                           misscanTypes.StringValue
	Grants                        []Grant
	BucketLocation                misscanTypes.StringValue
	AccelerateConfigurationStatus misscanTypes.StringValue
	LifecycleConfiguration        []Rules
	Objects                       []Contents
	Website                       *Website
}

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

type Logging struct {
	Metadata     misscanTypes.Metadata
	Enabled      misscanTypes.BoolValue
	TargetBucket misscanTypes.StringValue
}

type Versioning struct {
	Metadata  misscanTypes.Metadata
	Enabled   misscanTypes.BoolValue
	MFADelete misscanTypes.BoolValue
}

type Encryption struct {
	Metadata  misscanTypes.Metadata
	Enabled   misscanTypes.BoolValue
	Algorithm misscanTypes.StringValue
	KMSKeyId  misscanTypes.StringValue
}

type Rules struct {
	Metadata misscanTypes.Metadata
	Status   misscanTypes.StringValue
}

type Contents struct {
	Metadata misscanTypes.Metadata
}

type Website struct {
	Metadata misscanTypes.Metadata
}

type Grant struct {
	Metadata    misscanTypes.Metadata
	Grantee     Grantee
	Permissions misscanTypes.StringValueList
}

type Grantee struct {
	Metadata misscanTypes.Metadata
	URI      misscanTypes.StringValue
	Type     misscanTypes.StringValue
}
