package github

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type BranchProtection struct {
	Metadata             misscanTypes.Metadata
	RequireSignedCommits misscanTypes.BoolValue
}

func (b BranchProtection) RequiresSignedCommits() bool {
	return b.RequireSignedCommits.IsTrue()
}
