package emr

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	Metadata misscanTypes.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	Metadata     misscanTypes.Metadata
	Name         misscanTypes.StringValue
	ReleaseLabel misscanTypes.StringValue
	ServiceRole  misscanTypes.StringValue
}

type SecurityConfiguration struct {
	Metadata      misscanTypes.Metadata
	Name          misscanTypes.StringValue
	Configuration misscanTypes.StringValue
}
