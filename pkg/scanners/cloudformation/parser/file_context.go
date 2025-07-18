package parser

import (
	"github.com/samber/lo"

	"github.com/khulnasoft-lab/misscan/pkg/ignore"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type SourceFormat string

const (
	YamlSourceFormat SourceFormat = "yaml"
	JsonSourceFormat SourceFormat = "json"
)

type FileContexts []*FileContext

type FileContext struct {
	filepath     string
	lines        []string
	SourceFormat SourceFormat
	Ignores      ignore.Rules
	Parameters   map[string]*Parameter `json:"Parameters" yaml:"Parameters"`
	Resources    map[string]*Resource  `json:"Resources" yaml:"Resources"`
	Globals      map[string]*Resource  `json:"Globals" yaml:"Globals"`
	Mappings     map[string]any        `json:"Mappings,omitempty" yaml:"Mappings"`
	Conditions   map[string]Property   `json:"Conditions,omitempty" yaml:"Conditions"`
}

func (t *FileContext) GetResourceByLogicalID(name string) *Resource {
	for n, r := range t.Resources {
		if name == n {
			return r
		}
	}
	return nil
}

func (t *FileContext) GetResourcesByType(names ...string) []*Resource {
	var resources []*Resource
	for _, r := range t.Resources {
		for _, name := range names {
			if name == r.Type() {
				resources = append(resources, r)
			}
		}
	}
	return resources
}

func (t *FileContext) Metadata() misscanTypes.Metadata {
	rng := misscanTypes.NewRange(t.filepath, 1, len(t.lines), "", nil)

	return misscanTypes.NewMetadata(rng, NewCFReference("Template", rng).String())
}

// TODO: use map[string]string
func (t *FileContext) overrideParameters(params map[string]any) {
	for key := range t.Parameters {
		if val, ok := params[key]; ok {
			t.Parameters[key].UpdateDefault(val)
		}
	}
}

func (t *FileContext) missingParameterValues() []string {
	var missing []string
	for key := range t.Parameters {
		if t.Parameters[key].inner.Default == nil {
			missing = append(missing, key)
		}
	}
	return missing
}

func (t *FileContext) stripNullProperties() {
	for _, resource := range t.Resources {
		resource.properties = lo.OmitBy(resource.properties, func(_ string, v *Property) bool {
			return v.IsNil()
		})
	}
}
