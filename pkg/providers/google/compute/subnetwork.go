package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SubNetwork struct {
	Metadata       misscanTypes.Metadata
	Name           misscanTypes.StringValue
	EnableFlowLogs misscanTypes.BoolValue
}
