package datafactory

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	Metadata            misscanTypes.Metadata
	EnablePublicNetwork misscanTypes.BoolValue
}
