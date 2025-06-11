package dns

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	Metadata   misscanTypes.Metadata
	DNSSec     DNSSec
	Visibility misscanTypes.StringValue
}

type DNSSec struct {
	Metadata        misscanTypes.Metadata
	Enabled         misscanTypes.BoolValue
	DefaultKeySpecs []KeySpecs
}

type KeySpecs struct {
	Metadata  misscanTypes.Metadata
	Algorithm misscanTypes.StringValue
	KeyType   misscanTypes.StringValue
}
