package iam

import (
	"fmt"
	"strings"

	"github.com/khulnasoft-lab/misscan/pkg/concurrency"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/iamgo"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func (a *adapter) adaptPolicies(state *state.State) error {

	a.Tracker().SetServiceLabel("Discovering policies...")

	var nativePolicies []iamtypes.Policy

	input := &iamapi.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal,
	}
	for {
		policiesOutput, err := a.api.ListPolicies(a.Context(), input)
		if err != nil {
			return err
		}
		nativePolicies = append(nativePolicies, policiesOutput.Policies...)
		a.Tracker().SetTotalResources(len(nativePolicies))
		if !policiesOutput.IsTruncated {
			break
		}
		input.Marker = policiesOutput.Marker
	}

	a.Tracker().SetServiceLabel("Adapting policies...")

	state.AWS.IAM.Policies = concurrency.Adapt(nativePolicies, a.RootAdapter, a.adaptPolicy)
	return nil
}

func (a *adapter) adaptPolicy(apiPolicy iamtypes.Policy) (*iam.Policy, error) {

	if apiPolicy.Arn == nil {
		return nil, fmt.Errorf("policy arn not specified")
	}
	if apiPolicy.PolicyName == nil {
		return nil, fmt.Errorf("policy name not specified")
	}

	output, err := a.api.GetPolicyVersion(a.Context(), &iamapi.GetPolicyVersionInput{
		PolicyArn: apiPolicy.Arn,
		VersionId: apiPolicy.DefaultVersionId,
	})
	if err != nil {
		return nil, err
	}

	metadata := a.CreateMetadataFromARN(*apiPolicy.Arn)

	document, err := iamgo.ParseString(*output.PolicyVersion.Document)
	if err != nil {
		return nil, err
	}

	name := misscanTypes.StringDefault("", metadata)
	if apiPolicy.PolicyName != nil {
		name = misscanTypes.String(*apiPolicy.PolicyName, metadata)
	}

	return &iam.Policy{
		Metadata: metadata,
		Name:     name,
		Document: iam.Document{
			Metadata: metadata,
			Parsed:   *document,
		},
		Builtin: misscanTypes.Bool(strings.HasPrefix(*apiPolicy.Arn, "arn:aws:iam::aws:"), metadata),
	}, nil
}

func (a *adapter) adaptAttachedPolicy(apiPolicy iamtypes.AttachedPolicy) (*iam.Policy, error) {

	if apiPolicy.PolicyArn == nil {
		return nil, fmt.Errorf("policy arn not specified")
	}
	if apiPolicy.PolicyName == nil {
		return nil, fmt.Errorf("policy name not specified")
	}

	policyOutput, err := a.api.GetPolicy(a.Context(), &iamapi.GetPolicyInput{
		PolicyArn: apiPolicy.PolicyArn,
	})
	if err != nil {
		return nil, err
	}

	return a.adaptPolicy(*policyOutput.Policy)
}
