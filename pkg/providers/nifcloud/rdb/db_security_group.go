package rdb

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type DBSecurityGroup struct {
	Metadata    misscanTypes.Metadata
	Description misscanTypes.StringValue
	CIDRs       []misscanTypes.StringValue
}
