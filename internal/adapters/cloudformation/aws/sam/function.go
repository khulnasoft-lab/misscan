package sam

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/liamg/iamgo"
)

func getFunctions(cfFile parser.FileContext) (functions []sam.Function) {

	functionResources := cfFile.GetResourcesByType("AWS::Serverless::Function")
	for _, r := range functionResources {
		function := sam.Function{
			Metadata:        r.Metadata(),
			FunctionName:    r.GetStringProperty("FunctionName"),
			Tracing:         r.GetStringProperty("Tracing", sam.TracingModePassThrough),
			ManagedPolicies: nil,
			Policies:        nil,
		}

		setFunctionPolicies(r, &function)
		functions = append(functions, function)
	}

	return functions
}

func setFunctionPolicies(r *parser.Resource, function *sam.Function) {
	policies := r.GetProperty("Policies")
	if policies.IsNotNil() {
		if policies.IsString() {
			function.ManagedPolicies = append(function.ManagedPolicies, policies.AsStringValue())
		} else if policies.IsList() {
			for _, property := range policies.AsList() {
				if property.IsMap() {
					parsed, err := iamgo.Parse(property.GetJsonBytes(true))
					if err != nil {
						continue
					}
					policy := iam.Policy{
						Metadata: property.Metadata(),
						Name:     misscanTypes.StringDefault("", property.Metadata()),
						Document: iam.Document{
							Metadata: property.Metadata(),
							Parsed:   *parsed,
						},
						Builtin: misscanTypes.Bool(false, property.Metadata()),
					}
					function.Policies = append(function.Policies, policy)
				} else if property.IsString() {
					function.ManagedPolicies = append(function.ManagedPolicies, property.AsStringValue())
				}
			}
		}
	}
}
