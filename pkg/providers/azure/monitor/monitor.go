package monitor

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Monitor struct {
	LogProfiles []LogProfile
}

type LogProfile struct {
	Metadata        misscanTypes.Metadata
	RetentionPolicy RetentionPolicy
	Categories      []misscanTypes.StringValue
	Locations       []misscanTypes.StringValue
}

type RetentionPolicy struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	Days     misscanTypes.IntValue
}
