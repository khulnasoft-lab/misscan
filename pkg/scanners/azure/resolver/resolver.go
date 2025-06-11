package resolver

import (
	azure2 "github.com/khulnasoft-lab/misscan/pkg/scanners/azure"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/azure/expressions"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type Resolver interface {
	ResolveExpression(expression azure2.Value) azure2.Value
	SetDeployment(d *azure2.Deployment)
}

func NewResolver() Resolver {
	return &resolver{}
}

type resolver struct {
	deployment *azure2.Deployment
}

func (r *resolver) SetDeployment(d *azure2.Deployment) {
	r.deployment = d
}

func (r *resolver) ResolveExpression(expression azure2.Value) azure2.Value {
	if expression.Kind != azure2.KindExpression {
		return expression
	}
	if r.deployment == nil {
		panic("cannot resolve expression on nil deployment")
	}
	code := expression.AsString()

	resolved, err := r.resolveExpressionString(code, expression.GetMetadata())
	if err != nil {
		expression.Kind = azure2.KindUnresolvable
		return expression
	}
	return resolved
}

func (r *resolver) resolveExpressionString(code string, metadata misscanTypes.Metadata) (azure2.Value, error) {
	et, err := expressions.NewExpressionTree(code)
	if err != nil {
		return azure2.NullValue, err
	}

	evaluatedValue := et.Evaluate(r.deployment)
	return azure2.NewValue(evaluatedValue, metadata), nil
}
