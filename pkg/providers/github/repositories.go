package github

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Repository struct {
	Metadata            misscanTypes.Metadata
	Public              misscanTypes.BoolValue
	VulnerabilityAlerts misscanTypes.BoolValue
	Archived            misscanTypes.BoolValue
}
