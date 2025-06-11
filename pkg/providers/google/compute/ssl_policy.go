package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SSLPolicy struct {
	Metadata          misscanTypes.Metadata
	Name              misscanTypes.StringValue
	Profile           misscanTypes.StringValue
	MinimumTLSVersion misscanTypes.StringValue
}
