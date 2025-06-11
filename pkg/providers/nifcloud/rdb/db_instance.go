package rdb

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type DBInstance struct {
	Metadata                  misscanTypes.Metadata
	BackupRetentionPeriodDays misscanTypes.IntValue
	Engine                    misscanTypes.StringValue
	EngineVersion             misscanTypes.StringValue
	NetworkID                 misscanTypes.StringValue
	PublicAccess              misscanTypes.BoolValue
}
