package sam

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Application struct {
	Metadata     misscanTypes.Metadata
	LocationPath misscanTypes.StringValue
	Location     Location
}

type Location struct {
	Metadata        misscanTypes.Metadata
	ApplicationID   misscanTypes.StringValue
	SemanticVersion misscanTypes.StringValue
}
