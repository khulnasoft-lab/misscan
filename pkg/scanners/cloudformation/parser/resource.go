package parser

import (
	"io/fs"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"gopkg.in/yaml.v3"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	xjson "github.com/khulnasoft-lab/misscan/pkg/x/json"
)

type Resource struct {
	xjson.Location
	typ        string
	properties map[string]*Property
	ctx        *FileContext
	rng        misscanTypes.Range
	id         string
	comment    string
}

func (r *Resource) configureResource(id string, target fs.FS, filepath string, ctx *FileContext) {
	r.setId(id)
	r.setFile(target, filepath)
	r.setContext(ctx)
}

func (r *Resource) setId(id string) {
	r.id = id

	for n, p := range r.properties {
		p.setName(n)
	}
}

func (r *Resource) setFile(target fs.FS, filepath string) {
	r.rng = misscanTypes.NewRange(filepath, r.StartLine, r.EndLine, r.rng.GetSourcePrefix(), target)

	for _, p := range r.properties {
		p.setFileAndParentRange(target, filepath, r.rng)
	}
}

func (r *Resource) setContext(ctx *FileContext) {
	r.ctx = ctx

	for _, p := range r.properties {
		p.setLogicalResource(r.id)
		p.setContext(ctx)
	}
}

type resourceInner struct {
	Type       string               `json:"Type" yaml:"Type"`
	Properties map[string]*Property `json:"Properties" yaml:"Properties"`
}

func (r *Resource) UnmarshalYAML(node *yaml.Node) error {
	r.StartLine = node.Line - 1
	r.EndLine = calculateEndLine(node)
	r.comment = node.LineComment

	var i resourceInner
	if err := node.Decode(&i); err != nil {
		return err
	}
	r.typ = i.Type
	r.properties = i.Properties
	return nil
}

func (r *Resource) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var i resourceInner
	if err := json.UnmarshalDecode(dec, &i); err != nil {
		return err
	}
	r.typ = i.Type
	r.properties = i.Properties
	return nil
}

func (r *Resource) ID() string {
	return r.id
}

func (r *Resource) Type() string {
	return r.typ
}

func (r *Resource) Range() misscanTypes.Range {
	return r.rng
}

func (r *Resource) SourceFormat() SourceFormat {
	return r.ctx.SourceFormat
}

func (r *Resource) Metadata() misscanTypes.Metadata {
	return misscanTypes.NewMetadata(r.Range(), NewCFReference(r.id, r.rng).String())
}

func (r *Resource) IsNil() bool {
	return r.id == ""
}

func (r *Resource) GetProperty(path string) *Property {

	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	property := &Property{}

	if p, exists := r.properties[first]; exists {
		property = p
	}

	if len(pathParts) == 1 || property.IsNil() {
		if property.isFunction() {
			resolved, _ := property.resolveValue()
			return resolved
		}
		return property
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		return nestedProperty
	}

	return &Property{}
}

func (r *Resource) GetStringProperty(path string, defaultValue ...string) misscanTypes.StringValue {
	defVal := ""
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotString() {
		return r.StringDefault(defVal)
	}
	return prop.AsStringValue()
}

func (r *Resource) GetBoolProperty(path string, defaultValue ...bool) misscanTypes.BoolValue {
	defVal := false
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotBool() {
		return r.inferBool(prop, defVal)
	}
	return prop.AsBoolValue()
}

func (r *Resource) GetIntProperty(path string, defaultValue ...int) misscanTypes.IntValue {
	defVal := 0
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	prop := r.GetProperty(path)

	if prop.IsNotInt() {
		return r.IntDefault(defVal)
	}
	return prop.AsIntValue()
}

func (r *Resource) StringDefault(defaultValue string) misscanTypes.StringValue {
	return misscanTypes.StringDefault(defaultValue, r.Metadata())
}

func (r *Resource) BoolDefault(defaultValue bool) misscanTypes.BoolValue {
	return misscanTypes.BoolDefault(defaultValue, r.Metadata())
}

func (r *Resource) IntDefault(defaultValue int) misscanTypes.IntValue {
	return misscanTypes.IntDefault(defaultValue, r.Metadata())
}

func (r *Resource) inferBool(prop *Property, defaultValue bool) misscanTypes.BoolValue {
	if prop.IsString() {
		if prop.EqualTo("true", IgnoreCase) {
			return misscanTypes.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("yes", IgnoreCase) {
			return misscanTypes.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("1", IgnoreCase) {
			return misscanTypes.Bool(true, prop.Metadata())
		}
		if prop.EqualTo("false", IgnoreCase) {
			return misscanTypes.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("no", IgnoreCase) {
			return misscanTypes.Bool(false, prop.Metadata())
		}
		if prop.EqualTo("0", IgnoreCase) {
			return misscanTypes.Bool(false, prop.Metadata())
		}
	}

	if prop.IsInt() {
		if prop.EqualTo(0) {
			return misscanTypes.Bool(false, prop.Metadata())
		}
		if prop.EqualTo(1) {
			return misscanTypes.Bool(true, prop.Metadata())
		}
	}

	return r.BoolDefault(defaultValue)
}
