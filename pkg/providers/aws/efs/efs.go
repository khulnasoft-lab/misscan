package efs

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  misscanTypes.Metadata
	Encrypted misscanTypes.BoolValue
}
