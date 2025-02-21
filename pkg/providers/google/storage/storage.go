package storage

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata                       misscanTypes.Metadata
	Name                           misscanTypes.StringValue
	Location                       misscanTypes.StringValue
	EnableUniformBucketLevelAccess misscanTypes.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
	Encryption                     BucketEncryption
}

type BucketEncryption struct {
	Metadata          misscanTypes.Metadata
	DefaultKMSKeyName misscanTypes.StringValue
}
