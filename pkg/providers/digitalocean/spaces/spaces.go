package spaces

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Spaces struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata     misscanTypes.Metadata
	Name         misscanTypes.StringValue
	Objects      []Object
	ACL          misscanTypes.StringValue
	ForceDestroy misscanTypes.BoolValue
	Versioning   Versioning
}

type Versioning struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
}

type Object struct {
	Metadata misscanTypes.Metadata
	ACL      misscanTypes.StringValue
}
