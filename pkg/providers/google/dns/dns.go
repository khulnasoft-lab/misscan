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

func (m ManagedZone) IsPrivate() bool {
	return m.Visibility.EqualTo("private", misscanTypes.IgnoreCase)
}

type DNSSec struct {
	Metadata        misscanTypes.Metadata
	Enabled         misscanTypes.BoolValue
	DefaultKeySpecs KeySpecs
}

type KeySpecs struct {
	Metadata       misscanTypes.Metadata
	KeySigningKey  Key
	ZoneSigningKey Key
}

type Key struct {
	Metadata  misscanTypes.Metadata
	Algorithm misscanTypes.StringValue
}
