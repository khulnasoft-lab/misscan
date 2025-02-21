package nas

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type NASSecurityGroup struct {
	Metadata    misscanTypes.Metadata
	Description misscanTypes.StringValue
	CIDRs       []misscanTypes.StringValue
}
