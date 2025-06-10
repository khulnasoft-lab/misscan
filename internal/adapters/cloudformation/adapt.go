package cloudformation

import (
	"github.com/khulnasoft-lab/misscan/internal/adapters/cloudformation/aws"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
