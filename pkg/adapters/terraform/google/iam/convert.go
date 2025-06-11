package iam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func ParsePolicyBlock(block *terraform.Block) []iam.Binding {
	var bindings []iam.Binding
	for _, bindingBlock := range block.GetBlocks("binding") {
		binding := iam.Binding{
			Metadata:                      bindingBlock.GetMetadata(),
			Members:                       nil,
			Role:                          bindingBlock.GetAttribute("role").AsStringValueOrDefault("", bindingBlock),
			IncludesDefaultServiceAccount: misscanTypes.BoolDefault(false, bindingBlock.GetMetadata()),
		}
		membersAttr := bindingBlock.GetAttribute("members")
		members := membersAttr.AsStringValues().AsStrings()
		for _, member := range members {
			binding.Members = append(binding.Members, misscanTypes.String(member, membersAttr.GetMetadata()))
		}
		bindings = append(bindings, binding)
	}
	return bindings
}
