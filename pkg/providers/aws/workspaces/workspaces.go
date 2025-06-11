package workspaces

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type WorkSpaces struct {
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	Metadata   misscanTypes.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	Metadata   misscanTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}
