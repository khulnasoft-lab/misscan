package elb

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type ELB struct {
	LoadBalancers []LoadBalancer
}

const (
	TypeApplication = "application"
	TypeGateway     = "gateway"
	TypeNetwork     = "network"
	TypeClassic     = "classic"
)

type LoadBalancer struct {
	Metadata                misscanTypes.Metadata
	Type                    misscanTypes.StringValue
	DropInvalidHeaderFields misscanTypes.BoolValue
	Internal                misscanTypes.BoolValue
	Listeners               []Listener
}

type Listener struct {
	Metadata       misscanTypes.Metadata
	Protocol       misscanTypes.StringValue
	TLSPolicy      misscanTypes.StringValue
	DefaultActions []Action
}

type Action struct {
	Metadata misscanTypes.Metadata
	Type     misscanTypes.StringValue
}
