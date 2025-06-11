package documentdb

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type DocumentDB struct {
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	Metadata              misscanTypes.Metadata
	Identifier            misscanTypes.StringValue
	EnabledLogExports     []misscanTypes.StringValue
	BackupRetentionPeriod misscanTypes.IntValue
	Instances             []Instance
	StorageEncrypted      misscanTypes.BoolValue
	KMSKeyID              misscanTypes.StringValue
}

type Instance struct {
	Metadata misscanTypes.Metadata
	KMSKeyID misscanTypes.StringValue
}
