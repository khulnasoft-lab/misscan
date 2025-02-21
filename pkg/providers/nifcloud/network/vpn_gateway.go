package network

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type VpnGateway struct {
	Metadata      misscanTypes.Metadata
	SecurityGroup misscanTypes.StringValue
}
