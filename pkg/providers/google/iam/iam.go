package iam

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type IAM struct {
	Organizations                 []Organization
	WorkloadIdentityPoolProviders []WorkloadIdentityPoolProvider
	Projects                      []Project
	Folders                       []Folder
}

type Organization struct {
	Metadata misscanTypes.Metadata
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	Metadata misscanTypes.Metadata
	Members  []Member
	Bindings []Binding
}

type Project struct {
	Metadata          misscanTypes.Metadata
	AutoCreateNetwork misscanTypes.BoolValue
	Members           []Member
	Bindings          []Binding
}

type Binding struct {
	Metadata                      misscanTypes.Metadata
	Members                       []misscanTypes.StringValue
	Role                          misscanTypes.StringValue
	IncludesDefaultServiceAccount misscanTypes.BoolValue
}

type Member struct {
	Metadata              misscanTypes.Metadata
	Member                misscanTypes.StringValue
	Role                  misscanTypes.StringValue
	DefaultServiceAccount misscanTypes.BoolValue
}

type WorkloadIdentityPoolProvider struct {
	Metadata                       misscanTypes.Metadata
	WorkloadIdentityPoolId         misscanTypes.StringValue
	WorkloadIdentityPoolProviderId misscanTypes.StringValue
	AttributeCondition             misscanTypes.StringValue
}
