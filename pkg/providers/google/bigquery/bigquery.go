package bigquery

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type BigQuery struct {
	Datasets []Dataset
}

type Dataset struct {
	Metadata     misscanTypes.Metadata
	ID           misscanTypes.StringValue
	AccessGrants []AccessGrant
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	Metadata     misscanTypes.Metadata
	Role         misscanTypes.StringValue
	Domain       misscanTypes.StringValue
	SpecialGroup misscanTypes.StringValue
}
