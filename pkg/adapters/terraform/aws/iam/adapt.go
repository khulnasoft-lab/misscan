package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) iam.IAM {
	return iam.IAM{
		PasswordPolicy: adaptPasswordPolicy(modules),
		Policies:       adaptPolicies(modules),
		Groups:         adaptGroups(modules),
		Users:          adaptUsers(modules),
		Roles:          adaptRoles(modules),
	}
}
