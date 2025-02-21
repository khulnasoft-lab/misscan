package iam

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type IAM struct {
	Organizations                 []Organization
	WorkloadIdentityPoolProviders []WorkloadIdentityPoolProvider
}

type Organization struct {
	Metadata misscanTypes.Metadata
	Folders  []Folder
	Projects []Project
	Members  []Member
	Bindings []Binding
}

type Folder struct {
	Metadata misscanTypes.Metadata
	Folders  []Folder
	Projects []Project
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

func (p *IAM) AllProjects() []Project {
	var projects []Project
	for _, org := range p.Organizations {
		projects = append(projects, org.Projects...)
		for _, folder := range org.Folders {
			projects = append(projects, folder.Projects...)
			for _, desc := range folder.AllFolders() {
				projects = append(projects, desc.Projects...)
			}
		}
	}
	return projects
}

func (p *IAM) AllFolders() []Folder {
	var folders []Folder
	for _, org := range p.Organizations {
		folders = append(folders, org.Folders...)
		for _, folder := range org.Folders {
			folders = append(folders, folder.AllFolders()...)
		}
	}
	return folders
}

func (f *Folder) AllFolders() []Folder {
	var folders []Folder
	for _, folder := range f.Folders {
		folders = append(folders, folder)
		folders = append(folders, folder.AllFolders()...)
	}
	return folders
}
