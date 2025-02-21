package network

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Network struct {
	SecurityGroups         []SecurityGroup
	NetworkWatcherFlowLogs []NetworkWatcherFlowLog
}

type SecurityGroup struct {
	Metadata misscanTypes.Metadata
	Rules    []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata             misscanTypes.Metadata
	Outbound             misscanTypes.BoolValue
	Allow                misscanTypes.BoolValue
	SourceAddresses      []misscanTypes.StringValue
	SourcePorts          []PortRange
	DestinationAddresses []misscanTypes.StringValue
	DestinationPorts     []PortRange
	Protocol             misscanTypes.StringValue
}

type PortRange struct {
	Metadata misscanTypes.Metadata
	Start    int
	End      int
}

func (r PortRange) Includes(port int) bool {
	return port >= r.Start && port <= r.End
}

type NetworkWatcherFlowLog struct {
	Metadata        misscanTypes.Metadata
	RetentionPolicy RetentionPolicy
}

type RetentionPolicy struct {
	Metadata misscanTypes.Metadata
	Enabled  misscanTypes.BoolValue
	Days     misscanTypes.IntValue
}
