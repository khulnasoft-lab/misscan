package network

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type LoadBalancer struct {
	Metadata  misscanTypes.Metadata
	Listeners []LoadBalancerListener
}

type LoadBalancerListener struct {
	Metadata  misscanTypes.Metadata
	Protocol  misscanTypes.StringValue
	TLSPolicy misscanTypes.StringValue
}
