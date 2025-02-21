package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type ProjectMetadata struct {
	Metadata      misscanTypes.Metadata
	EnableOSLogin misscanTypes.BoolValue
}
