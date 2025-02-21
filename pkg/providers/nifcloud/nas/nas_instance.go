package nas

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type NASInstance struct {
	Metadata  misscanTypes.Metadata
	NetworkID misscanTypes.StringValue
}
