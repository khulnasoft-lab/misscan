package iam

import (
	"fmt"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"

	"github.com/khulnasoft-lab/iamgo"
)

func getPolicies(ctx parser.FileContext) (policies []iam.Policy) {
	for _, policyResource := range ctx.GetResourcesByType("AWS::IAM::Policy") {

		policy := iam.Policy{
			Metadata: policyResource.Metadata(),
			Name:     policyResource.GetStringProperty("PolicyName"),
			Document: iam.Document{
				Metadata: policyResource.Metadata(),
				Parsed:   iamgo.Document{},
			},
			Builtin: misscanTypes.Bool(false, policyResource.Metadata()),
		}

		if policyProp := policyResource.GetProperty("PolicyDocument"); policyProp.IsNotNil() {
			doc, err := iamgo.Parse(policyProp.GetJsonBytes())
			if err != nil {
				continue
			}
			policy.Document.Parsed = *doc
		}

		policies = append(policies, policy)
	}
	return policies
}

func getRoles(ctx parser.FileContext) (roles []iam.Role) {
	for _, roleResource := range ctx.GetResourcesByType("AWS::IAM::Role") {
		policyProp := roleResource.GetProperty("Policies")
		roleName := roleResource.GetStringProperty("RoleName")

		roles = append(roles, iam.Role{
			Metadata: roleResource.Metadata(),
			Name:     roleName,
			Policies: getPoliciesDocs(policyProp),
		})
	}
	return roles
}

func getUsers(ctx parser.FileContext) (users []iam.User) {
	for _, userResource := range ctx.GetResourcesByType("AWS::IAM::User") {
		policyProp := userResource.GetProperty("Policies")
		userName := userResource.GetStringProperty("UserName")

		users = append(users, iam.User{
			Metadata:   userResource.Metadata(),
			Name:       userName,
			LastAccess: misscanTypes.TimeUnresolvable(userResource.Metadata()),
			Policies:   getPoliciesDocs(policyProp),
			AccessKeys: getAccessKeys(ctx, userName.Value()),
		})
	}
	return users
}

func getAccessKeys(ctx parser.FileContext, username string) (accessKeys []iam.AccessKey) {
	// TODO: also search for a key by the logical id of the resource
	for _, keyResource := range ctx.GetResourcesByType("AWS::IAM::AccessKey") {
		keyUsername := keyResource.GetStringProperty("UserName")
		if !keyUsername.EqualTo(username) {
			continue
		}
		active := misscanTypes.BoolDefault(false, keyResource.Metadata())
		if statusProp := keyResource.GetProperty("Status"); statusProp.IsString() {
			active = misscanTypes.Bool(statusProp.AsString() == "Active", statusProp.Metadata())
		}

		accessKeys = append(accessKeys, iam.AccessKey{
			Metadata:     keyResource.Metadata(),
			AccessKeyId:  misscanTypes.StringUnresolvable(keyResource.Metadata()),
			CreationDate: misscanTypes.TimeUnresolvable(keyResource.Metadata()),
			LastAccess:   misscanTypes.TimeUnresolvable(keyResource.Metadata()),
			Active:       active,
		})
	}
	return accessKeys
}

func getGroups(ctx parser.FileContext) (groups []iam.Group) {
	for _, groupResource := range ctx.GetResourcesByType("AWS::IAM::Group") {
		policyProp := groupResource.GetProperty("Policies")
		groupName := groupResource.GetStringProperty("GroupName")

		groups = append(groups, iam.Group{
			Metadata: groupResource.Metadata(),
			Name:     groupName,
			Policies: getPoliciesDocs(policyProp),
		})
	}
	return groups
}

func getPoliciesDocs(policiesProp *parser.Property) []iam.Policy {
	var policies []iam.Policy

	for _, policy := range policiesProp.AsList() {
		policyProp := policy.GetProperty("PolicyDocument")
		policyName := policy.GetStringProperty("PolicyName")

		doc, err := iamgo.Parse(policyProp.GetJsonBytes())
		if err != nil {
			continue
		}

		policies = append(policies, iam.Policy{
			Metadata: policyProp.Metadata(),
			Name:     policyName,
			Document: iam.Document{
				Metadata: policyProp.Metadata(),
				Parsed:   *doc,
			},
			Builtin: misscanTypes.Bool(false, policyProp.Metadata()),
		})
	}
	return policies
}
