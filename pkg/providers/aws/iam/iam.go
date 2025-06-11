package iam

import (
	"github.com/khulnasoft-lab/iamgo"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type IAM struct {
	PasswordPolicy     PasswordPolicy
	Policies           []Policy
	Groups             []Group
	Users              []User
	Roles              []Role
	ServerCertificates []ServerCertificate
}

type ServerCertificate struct {
	Metadata   misscanTypes.Metadata
	Expiration misscanTypes.TimeValue
}

type Policy struct {
	Metadata misscanTypes.Metadata
	Name     misscanTypes.StringValue
	Document Document
	Builtin  misscanTypes.BoolValue
}

type Document struct {
	Metadata misscanTypes.Metadata
	Parsed   iamgo.Document
	IsOffset bool
	HasRefs  bool
}

func (d Document) ToRego() any {
	m := d.Metadata
	doc, _ := d.Parsed.MarshalJSON()
	input := map[string]any{
		"filepath":     m.Range().GetFilename(),
		"startline":    m.Range().GetStartLine(),
		"endline":      m.Range().GetEndLine(),
		"managed":      m.IsManaged(),
		"explicit":     m.IsExplicit(),
		"value":        string(doc),
		"sourceprefix": m.Range().GetSourcePrefix(),
		"fskey":        misscanTypes.CreateFSKey(m.Range().GetFS()),
		"resource":     m.Reference(),
	}

	if m.Parent() != nil {
		input["parent"] = m.Parent().ToRego()
	}

	return input
}

type Group struct {
	Metadata misscanTypes.Metadata
	Name     misscanTypes.StringValue
	Policies []Policy
}

type User struct {
	Metadata   misscanTypes.Metadata
	Name       misscanTypes.StringValue
	Policies   []Policy
	AccessKeys []AccessKey
	MFADevices []MFADevice
	LastAccess misscanTypes.TimeValue
}

type MFADevice struct {
	Metadata  misscanTypes.Metadata
	IsVirtual misscanTypes.BoolValue
}

type AccessKey struct {
	Metadata     misscanTypes.Metadata
	AccessKeyId  misscanTypes.StringValue
	Active       misscanTypes.BoolValue
	CreationDate misscanTypes.TimeValue
	LastAccess   misscanTypes.TimeValue
}

type Role struct {
	Metadata misscanTypes.Metadata
	Name     misscanTypes.StringValue
	Policies []Policy
}

func (d Document) MetadataFromIamGo(r ...iamgo.Range) misscanTypes.Metadata {
	m := d.Metadata
	if d.HasRefs {
		return m
	}
	newRange := m.Range()
	var start int
	if !d.IsOffset {
		start = newRange.GetStartLine()
	}
	for _, rng := range r {
		newRange := misscanTypes.NewRange(
			newRange.GetLocalFilename(),
			start+rng.StartLine,
			start+rng.EndLine,
			newRange.GetSourcePrefix(),
			newRange.GetFS(),
		)
		m = misscanTypes.NewMetadata(newRange, m.Reference()).WithParent(m)
	}
	return m
}
