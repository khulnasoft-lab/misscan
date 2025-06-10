package parser

import (
	"fmt"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type CFReference struct {
	logicalId     string
	resourceRange misscanTypes.Range
	resolvedValue Property
}

func NewCFReference(id string, resourceRange misscanTypes.Range) CFReference {
	return CFReference{
		logicalId:     id,
		resourceRange: resourceRange,
	}
}

func NewCFReferenceWithValue(resourceRange misscanTypes.Range, resolvedValue Property, logicalId string) CFReference {
	return CFReference{
		resourceRange: resourceRange,
		resolvedValue: resolvedValue,
		logicalId:     logicalId,
	}
}

func (cf CFReference) String() string {
	return cf.resourceRange.String()
}

func (cf CFReference) LogicalID() string {
	return cf.logicalId
}

func (cf CFReference) ResourceRange() misscanTypes.Range {
	return cf.resourceRange
}

func (cf CFReference) PropertyRange() misscanTypes.Range {
	if cf.resolvedValue.IsNotNil() {
		return cf.resolvedValue.Range()
	}
	return misscanTypes.Range{}
}

func (cf CFReference) DisplayValue() string {
	if cf.resolvedValue.IsNotNil() {
		return fmt.Sprintf("%v", cf.resolvedValue.RawValue())
	}
	return ""
}

func (cf *CFReference) Comment() string {
	return cf.resolvedValue.Comment()
}
