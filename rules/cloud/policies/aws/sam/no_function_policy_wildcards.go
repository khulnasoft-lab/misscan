package sam

import (
	"strings"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/severity"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/rules"

	"github.com/khulnasoft-lab/misscan/pkg/providers"

	"github.com/khulnasoft-lab/iamgo"
)

var CheckNoFunctionPolicyWildcards = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0114",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "no-function-policy-wildcards",
		Summary:     "Function policies should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-policies",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoFunctionPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoFunctionPolicyWildcardsBadExamples,
			Links:               cloudFormationNoFunctionPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoFunctionPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {

		for _, function := range s.AWS.SAM.Functions {
			if function.Metadata.IsUnmanaged() {
				continue
			}

			for _, document := range function.Policies {
				policy := document.Document.Parsed
				statements, _ := policy.Statements()
				for _, statement := range statements {
					results = checkStatement(document.Document, statement, results)
				}
			}
		}
		return
	},
)

func checkStatement(document iam.Document, statement iamgo.Statement, results scan.Results) scan.Results {
	effect, _ := statement.Effect()
	if effect != iamgo.EffectAllow {
		return results
	}
	actions, r := statement.Actions()
	for _, action := range actions {
		if strings.Contains(action, "*") {
			results.Add(
				"Policy document uses a wildcard action.",
				document.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(document)
		}
	}
	resources, r := statement.Resources()
	for _, resource := range resources {
		if strings.Contains(resource, "*") {
			if ok, _ := iam.IsWildcardAllowed(actions...); !ok {
				if strings.HasSuffix(resource, "/*") && strings.HasPrefix(resource, "arn:aws:s3") {
					continue
				}
				results.Add(
					"Policy document uses a wildcard resource for sensitive action(s).",
					document.MetadataFromIamGo(statement.Range(), r),
				)
			} else {
				results.AddPassed(document)
			}
		} else {
			results.AddPassed(document)
		}
	}
	principals, _ := statement.Principals()
	if all, r := principals.All(); all {
		results.Add(
			"Policy document uses a wildcard principal.",
			document.MetadataFromIamGo(statement.Range(), r),
		)
	}
	aws, r := principals.AWS()
	for _, principal := range aws {
		if strings.Contains(principal, "*") {
			results.Add(
				"Policy document uses a wildcard principal.",
				document.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(document)
		}
	}
	return results
}
