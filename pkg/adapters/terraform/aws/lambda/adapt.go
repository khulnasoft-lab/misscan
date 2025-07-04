package lambda

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/lambda"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) lambda.Lambda {

	adapter := adapter{
		permissionIDs: modules.GetChildResourceIDMapByType("aws_lambda_permission"),
	}

	return lambda.Lambda{
		Functions: adapter.adaptFunctions(modules),
	}
}

type adapter struct {
	permissionIDs terraform.ResourceIDResolutions
}

func (a *adapter) adaptFunctions(modules terraform.Modules) []lambda.Function {

	var functions []lambda.Function
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_lambda_function") {
			functions = append(functions, a.adaptFunction(resource, modules, a.permissionIDs))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.permissionIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := lambda.Function{
			Metadata: misscanTypes.NewUnmanagedMetadata(),
			Tracing: lambda.Tracing{
				Metadata: misscanTypes.NewUnmanagedMetadata(),
				Mode:     misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			},
			Permissions: nil,
		}
		for _, permission := range orphanResources {
			orphanage.Permissions = append(orphanage.Permissions, a.adaptPermission(permission))
		}
		functions = append(functions, orphanage)
	}

	return functions
}

func (a *adapter) adaptFunction(function *terraform.Block, modules terraform.Modules, orphans terraform.ResourceIDResolutions) lambda.Function {
	var permissions []lambda.Permission
	for _, module := range modules {
		for _, p := range module.GetResourcesByType("aws_lambda_permission") {
			if referencedBlock, err := module.GetReferencedBlock(p.GetAttribute("function_name"), p); err == nil && referencedBlock == function {
				permissions = append(permissions, a.adaptPermission(p))
				delete(orphans, p.ID())
			}
		}
	}

	return lambda.Function{
		Metadata:    function.GetMetadata(),
		Tracing:     a.adaptTracing(function),
		Permissions: permissions,
	}
}

func (a *adapter) adaptTracing(function *terraform.Block) lambda.Tracing {
	if tracingConfig := function.GetBlock("tracing_config"); tracingConfig.IsNotNil() {
		return lambda.Tracing{
			Metadata: tracingConfig.GetMetadata(),
			Mode:     tracingConfig.GetAttribute("mode").AsStringValueOrDefault("", tracingConfig),
		}
	}

	return lambda.Tracing{
		Metadata: function.GetMetadata(),
		Mode:     misscanTypes.StringDefault("", function.GetMetadata()),
	}
}

func (a *adapter) adaptPermission(permission *terraform.Block) lambda.Permission {
	sourceARNAttr := permission.GetAttribute("source_arn")
	sourceARN := sourceARNAttr.AsStringValueOrDefault("", permission)

	if refs := sourceARNAttr.AllReferences(); len(refs) > 0 {
		sourceARN = misscanTypes.String(refs[0].NameLabel(), sourceARNAttr.GetMetadata())
	}

	return lambda.Permission{
		Metadata:  permission.GetMetadata(),
		Principal: permission.GetAttribute("principal").AsStringValueOrDefault("", permission),
		SourceARN: sourceARN,
	}
}
