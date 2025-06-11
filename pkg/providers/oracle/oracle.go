package oracle

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Oracle struct {
	Compute Compute
}

type Compute struct {
	AddressReservations []AddressReservation
}

type AddressReservation struct {
	Metadata misscanTypes.Metadata
	Pool     misscanTypes.StringValue // e.g. public-pool
}
