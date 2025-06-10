package github

import (
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/github/branch_protections"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/github/repositories"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/github/secrets"
	"github.com/khulnasoft-lab/misscan/pkg/providers/github"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) github.GitHub {
	return github.GitHub{
		Repositories:       repositories.Adapt(modules),
		EnvironmentSecrets: secrets.Adapt(modules),
		BranchProtections:  branch_protections.Adapt(modules),
	}
}
