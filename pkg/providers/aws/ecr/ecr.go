package ecr

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type ECR struct {
	Repositories []Repository
}

type Repository struct {
	Metadata           misscanTypes.Metadata
	ImageScanning      ImageScanning
	ImageTagsImmutable misscanTypes.BoolValue
	Policies           []iam.Policy
	Encryption         Encryption
}

type ImageScanning struct {
	Metadata   misscanTypes.Metadata
	ScanOnPush misscanTypes.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	Metadata misscanTypes.Metadata
	Type     misscanTypes.StringValue
	KMSKeyID misscanTypes.StringValue
}
