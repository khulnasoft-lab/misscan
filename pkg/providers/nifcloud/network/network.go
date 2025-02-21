package network

import misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

type Network struct {
	ElasticLoadBalancers []ElasticLoadBalancer
	LoadBalancers        []LoadBalancer
	Routers              []Router
	VpnGateways          []VpnGateway
}

type NetworkInterface struct {
	Metadata     misscanTypes.Metadata
	NetworkID    misscanTypes.StringValue
	IsVipNetwork misscanTypes.BoolValue
}
