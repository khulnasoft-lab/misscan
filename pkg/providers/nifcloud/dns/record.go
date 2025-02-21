package dns

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

const ZoneRegistrationAuthTxt = "nifty-dns-verify="

type Record struct {
	Metadata misscanTypes.Metadata
	Type     misscanTypes.StringValue
	Record   misscanTypes.StringValue
}
