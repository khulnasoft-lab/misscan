package neptune

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata         misscanTypes.Metadata
	Logging          Logging
	StorageEncrypted misscanTypes.BoolValue
	KMSKeyID         misscanTypes.StringValue
}

type Logging struct {
	Metadata misscanTypes.Metadata
	Audit    misscanTypes.BoolValue
}
