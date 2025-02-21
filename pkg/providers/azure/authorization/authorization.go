package authorization

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	Metadata         misscanTypes.Metadata
	Permissions      []Permission
	AssignableScopes []misscanTypes.StringValue
}

type Permission struct {
	Metadata misscanTypes.Metadata
	Actions  []misscanTypes.StringValue
}
