package parser

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type CFReference struct {
	logicalId     string
	resourceRange misscanTypes.Range
}

func NewCFReference(id string, resourceRange misscanTypes.Range) CFReference {
	return CFReference{
		logicalId:     id,
		resourceRange: resourceRange,
	}
}

func (cf CFReference) String() string {
	return cf.resourceRange.String()
}
