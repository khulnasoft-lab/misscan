package compute

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	Metadata misscanTypes.Metadata
	UserData misscanTypes.StringValue // not b64 encoded pls
}
