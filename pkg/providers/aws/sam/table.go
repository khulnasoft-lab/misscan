package sam

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SimpleTable struct {
	Metadata         misscanTypes.Metadata
	TableName        misscanTypes.StringValue
	SSESpecification SSESpecification
}

type SSESpecification struct {
	Metadata misscanTypes.Metadata

	Enabled        misscanTypes.BoolValue
	KMSMasterKeyID misscanTypes.StringValue
}
