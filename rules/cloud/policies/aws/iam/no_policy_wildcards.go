package iam

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/khulnasoft-lab/misscan/pkg/framework"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/severity"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/rules"

	"github.com/khulnasoft-lab/misscan/pkg/providers"

	"github.com/khulnasoft-lab/iamgo"
)

var (
	//arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*
	cloudwatchLogStreamResourceRegex = regexp.MustCompile(`^arn:aws:logs:.*:.+:log-group:.+:\*`)
)

var CheckNoPolicyWildcards = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0057",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "no-policy-wildcards",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_4: {"1.16"},
		},
		Summary:     "IAM policy should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPolicyWildcardsGoodExamples,
			BadExamples:         terraformNoPolicyWildcardsBadExamples,
			Links:               terraformNoPolicyWildcardsLinks,
			RemediationMarkdown: terraformNoPolicyWildcardsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoPolicyWildcardsBadExamples,
			Links:               cloudFormationNoPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, policy := range s.AWS.IAM.Policies {
			if policy.Builtin.IsTrue() {
				continue
			}
			results = checkPolicy(policy.Document, results)
		}
		for _, group := range s.AWS.IAM.Groups {
			for _, policy := range group.Policies {
				if policy.Builtin.IsTrue() {
					continue
				}
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, user := range s.AWS.IAM.Users {
			for _, policy := range user.Policies {
				if policy.Builtin.IsTrue() {
					continue
				}
				results = checkPolicy(policy.Document, results)
			}
		}
		for _, role := range s.AWS.IAM.Roles {
			for _, policy := range role.Policies {
				if policy.Builtin.IsTrue() {
					continue
				}
				results = checkPolicy(policy.Document, results)
			}
		}
		return results
	},
)

func checkPolicy(src iam.Document, results scan.Results) scan.Results {
	statements, _ := src.Parsed.Statements()
	for _, statement := range statements {
		results = checkStatement(src, statement, results)
	}
	return results
}

// nolint
func checkStatement(src iam.Document, statement iamgo.Statement, results scan.Results) scan.Results {
	effect, _ := statement.Effect()
	if effect != iamgo.EffectAllow {
		return results
	}

	actions, r := statement.Actions()
	for _, action := range actions {
		if strings.Contains(action, "*") {
			results.Add(
				fmt.Sprintf(
					"IAM policy document uses wildcarded action '%s'",
					actions[0],
				),
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(src)
		}
	}

	resources, r := statement.Resources()
	for _, resource := range resources {
		if strings.Contains(resource, "*") {
			if allowed, action := iam.IsWildcardAllowed(actions...); !allowed {
				if strings.HasSuffix(resource, "/*") && strings.HasPrefix(resource, "arn:aws:s3") {
					continue
				}
				if cloudwatchLogStreamResourceRegex.MatchString(resource) {
					continue
				}

				results.Add(
					fmt.Sprintf("IAM policy document uses sensitive action '%s' on wildcarded resource '%s'", action, resources[0]),
					src.MetadataFromIamGo(statement.Range(), r),
				)
			} else {
				results.AddPassed(src)
			}
		} else {
			results.AddPassed(src)
		}
	}
	principals, _ := statement.Principals()
	if all, r := principals.All(); all {
		results.Add(
			"IAM policy document uses wildcarded principal.",
			src.MetadataFromIamGo(statement.Range(), r),
		)
	}
	aws, r := principals.AWS()
	for _, principal := range aws {
		if strings.Contains(principal, "*") {
			results.Add(
				"IAM policy document uses wildcarded principal.",
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			results.AddPassed(src)
		}
	}

	return results
}
