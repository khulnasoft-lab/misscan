package ec2

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Subnet struct {
	Metadata            misscanTypes.Metadata
	MapPublicIpOnLaunch misscanTypes.BoolValue
}
