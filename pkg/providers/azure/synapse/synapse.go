package synapse

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	Metadata                    misscanTypes.Metadata
	EnableManagedVirtualNetwork misscanTypes.BoolValue
}
