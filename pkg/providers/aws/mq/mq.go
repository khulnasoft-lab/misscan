package mq

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type MQ struct {
	Brokers []Broker
}

type Broker struct {
	Metadata     misscanTypes.Metadata
	PublicAccess misscanTypes.BoolValue
	Logging      Logging
}

type Logging struct {
	Metadata misscanTypes.Metadata
	General  misscanTypes.BoolValue
	Audit    misscanTypes.BoolValue
}
