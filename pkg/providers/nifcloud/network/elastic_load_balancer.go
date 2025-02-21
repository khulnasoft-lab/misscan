package network

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type ElasticLoadBalancer struct {
	Metadata          misscanTypes.Metadata
	NetworkInterfaces []NetworkInterface
	Listeners         []ElasticLoadBalancerListener
}

type ElasticLoadBalancerListener struct {
	Metadata misscanTypes.Metadata
	Protocol misscanTypes.StringValue
}
