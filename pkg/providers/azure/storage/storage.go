package storage

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Storage struct {
	Accounts []Account
}

type Account struct {
	Metadata            misscanTypes.Metadata
	NetworkRules        []NetworkRule
	EnforceHTTPS        misscanTypes.BoolValue
	Containers          []Container
	QueueProperties     QueueProperties
	MinimumTLSVersion   misscanTypes.StringValue
	Queues              []Queue
	PublicNetworkAccess misscanTypes.BoolValue
}

type Queue struct {
	Metadata misscanTypes.Metadata
	Name     misscanTypes.StringValue
}

type QueueProperties struct {
	Metadata      misscanTypes.Metadata
	EnableLogging misscanTypes.BoolValue
}

type NetworkRule struct {
	Metadata       misscanTypes.Metadata
	Bypass         []misscanTypes.StringValue
	AllowByDefault misscanTypes.BoolValue
}

const (
	PublicAccessOff       = "off"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"
)

type Container struct {
	Metadata     misscanTypes.Metadata
	PublicAccess misscanTypes.StringValue
}
