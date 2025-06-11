package eks

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type EKS struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            misscanTypes.Metadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled misscanTypes.BoolValue
	PublicAccessCIDRs   []misscanTypes.StringValue
}

type Logging struct {
	Metadata          misscanTypes.Metadata
	API               misscanTypes.BoolValue
	Audit             misscanTypes.BoolValue
	Authenticator     misscanTypes.BoolValue
	ControllerManager misscanTypes.BoolValue
	Scheduler         misscanTypes.BoolValue
}

type Encryption struct {
	Metadata misscanTypes.Metadata
	Secrets  misscanTypes.BoolValue
	KMSKeyID misscanTypes.StringValue
}
