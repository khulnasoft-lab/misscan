package datalake

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	Metadata         misscanTypes.Metadata
	EnableEncryption misscanTypes.BoolValue
}
