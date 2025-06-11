package kinesis

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	Metadata   misscanTypes.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	Metadata misscanTypes.Metadata
	Type     misscanTypes.StringValue
	KMSKeyID misscanTypes.StringValue
}
