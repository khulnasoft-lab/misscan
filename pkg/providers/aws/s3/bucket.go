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
	BucketLocation                misscanTypes.StringValue
	AccelerateConfigurationStatus misscanTypes.StringValue
	LifecycleConfiguration        []Rules
	Objects                       []Contents
	Website                       *Website
}

func (b *Bucket) HasPublicExposureACL() bool {
	for _, publicACL := range []string{"public-read", "public-read-write", "website", "authenticated-read"} {
		if b.ACL.EqualTo(publicACL) {
			// if there is a public access block, check the public ACL blocks
			if b.PublicAccessBlock != nil && b.PublicAccessBlock.Metadata.IsManaged() {
				return b.PublicAccessBlock.IgnorePublicACLs.IsFalse() && b.PublicAccessBlock.BlockPublicACLs.IsFalse()
			}
			return true
		}
	}
	return false
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
