package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Disk struct {
	Metadata   misscanTypes.Metadata
	Name       misscanTypes.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	Metadata   misscanTypes.Metadata
	RawKey     misscanTypes.BytesValue
	KMSKeyLink misscanTypes.StringValue
}
