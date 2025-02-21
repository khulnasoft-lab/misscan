package rds

import (
	"github.com/khulnasoft-lab/misscan/pkg/types"
)

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	Metadata types.Metadata
}
