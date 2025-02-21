package computing

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Instance struct {
	Metadata          misscanTypes.Metadata
	SecurityGroup     misscanTypes.StringValue
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	Metadata  misscanTypes.Metadata
	NetworkID misscanTypes.StringValue
}
