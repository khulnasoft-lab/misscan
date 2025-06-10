package rdb

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/rdb"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) rdb.RDB {
	return rdb.RDB{
		DBSecurityGroups: adaptDBSecurityGroups(modules),
		DBInstances:      adaptDBInstances(modules),
	}
}
