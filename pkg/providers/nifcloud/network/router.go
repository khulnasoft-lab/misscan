package network

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Router struct {
	Metadata          misscanTypes.Metadata
	SecurityGroup     misscanTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
