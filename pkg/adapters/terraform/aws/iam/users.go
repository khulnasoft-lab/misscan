package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func adaptUsers(modules terraform.Modules) []iam.User {
	var users []iam.User

	for _, userBlock := range modules.GetResourcesByType("aws_iam_user") {
		user := iam.User{
			Metadata:   userBlock.GetMetadata(),
			Name:       userBlock.GetAttribute("name").AsStringValueOrDefault("", userBlock),
			LastAccess: misscanTypes.TimeUnresolvable(userBlock.GetMetadata()),
		}

		if policy, ok := applyForDependentResource(
			modules, userBlock.ID(), "name", "aws_iam_user_policy", "user", findPolicy(modules),
		); ok && policy != nil {
			user.Policies = append(user.Policies, *policy)
		}

		if policy, ok := applyForDependentResource(
			modules, userBlock.ID(), "name", "aws_iam_user_policy_attachment", "user", findAttachmentPolicy(modules),
		); ok && policy != nil {
			user.Policies = append(user.Policies, *policy)
		}

		if accessKey, ok := applyForDependentResource(
			modules, userBlock.ID(), "name", "aws_iam_access_key", "user", adaptAccessKey,
		); ok {
			user.AccessKeys = append(user.AccessKeys, accessKey)
		}

		users = append(users, user)
	}
	return users

}

func adaptAccessKey(block *terraform.Block) iam.AccessKey {

	active := misscanTypes.BoolDefault(true, block.GetMetadata())
	if activeAttr := block.GetAttribute("status"); activeAttr.IsString() {
		active = misscanTypes.Bool(activeAttr.Equals("Active"), activeAttr.GetMetadata())
	}
	return iam.AccessKey{
		Metadata:     block.GetMetadata(),
		AccessKeyId:  misscanTypes.StringUnresolvable(block.GetMetadata()),
		CreationDate: misscanTypes.TimeUnresolvable(block.GetMetadata()),
		LastAccess:   misscanTypes.TimeUnresolvable(block.GetMetadata()),
		Active:       active,
	}
}
