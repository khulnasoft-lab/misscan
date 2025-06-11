package ec2

import misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

type RequestedAMI struct {
	Metadata misscanTypes.Metadata
	Owners   misscanTypes.StringValueList
}
