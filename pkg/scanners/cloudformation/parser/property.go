package parser

import (
	"fmt"
	"io/fs"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"gopkg.in/yaml.v3"

	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/cftypes"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	xjson "github.com/khulnasoft-lab/misscan/pkg/x/json"
)

type EqualityOptions = int

const (
	IgnoreCase EqualityOptions = iota
)

type Property struct {
	xjson.Location
	ctx         *FileContext
	Type        cftypes.CfType
	Value       any `json:"Value" yaml:"Value"`
	name        string
	comment     string
	rng         misscanTypes.Range
	parentRange misscanTypes.Range
	logicalId   string
	unresolved  bool
}

func (p *Property) Comment() string {
	return p.comment
}

func (p *Property) setName(name string) {
	p.name = name
	if p.Type == cftypes.Map {
		for n, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setName(n)
		}
	}
}

func (p *Property) setContext(ctx *FileContext) {
	p.ctx = ctx

	if p.IsMap() {
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setContext(ctx)
		}
	}

	if p.IsList() {
		for _, subProp := range p.AsList() {
			subProp.setContext(ctx)
		}
	}
}

func (p *Property) setFileAndParentRange(target fs.FS, filepath string, parentRange misscanTypes.Range) {
	p.rng = misscanTypes.NewRange(filepath, p.StartLine, p.EndLine, p.rng.GetSourcePrefix(), target)
	p.parentRange = parentRange

	switch p.Type {
	case cftypes.Map:
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setFileAndParentRange(target, filepath, parentRange)
		}
	case cftypes.List:
		for _, subProp := range p.AsList() {
			if subProp == nil {
				continue
			}
			subProp.setFileAndParentRange(target, filepath, parentRange)
		}
	}
}

func (p *Property) UnmarshalYAML(node *yaml.Node) error {
	p.StartLine = node.Line
	p.EndLine = calculateEndLine(node)
	p.comment = node.LineComment
	return setPropertyValueFromYaml(node, p)
}

func (p *Property) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var valPtr any
	var nodeType cftypes.CfType

	switch k := dec.PeekKind(); k {
	case 't', 'f':
		valPtr = new(bool)
		nodeType = cftypes.Bool
	case '"':
		valPtr = new(string)
		nodeType = cftypes.String
	case '0':
		return p.parseNumericValue(dec)
	case '[', 'n':
		valPtr = new([]*Property)
		nodeType = cftypes.List
	case '{':
		valPtr = new(map[string]*Property)
		nodeType = cftypes.Map
	case 0:
		return dec.SkipValue()
	default:
		return fmt.Errorf("unexpected token kind %q at %d", k.String(), dec.InputOffset())
	}

	if err := json.UnmarshalDecode(dec, valPtr); err != nil {
		return err
	}

	p.Value = reflect.ValueOf(valPtr).Elem().Interface()
	p.Type = nodeType
	return nil
}

func (p *Property) parseNumericValue(dec *jsontext.Decoder) error {
	raw, err := dec.ReadValue()
	if err != nil {
		return err
	}
	strVal := string(raw)

	if v, err := strconv.ParseInt(strVal, 10, 64); err == nil {
		p.Value = int(v)
		p.Type = cftypes.Int
		return nil
	}
	if v, err := strconv.ParseFloat(strVal, 64); err == nil {
		p.Value = v
		p.Type = cftypes.Float64
		return nil
	}
	return fmt.Errorf("invalid numeric value: %q", strVal)
}

func (p *Property) Metadata() misscanTypes.Metadata {
	return misscanTypes.NewMetadata(p.rng, p.name).
		WithParent(misscanTypes.NewMetadata(p.parentRange, p.logicalId))
}

func (p *Property) isFunction() bool {
	if p == nil {
		return false
	}
	if p.Type == cftypes.Map {
		for n := range p.AsMap() {
			return IsIntrinsic(n)
		}
	}
	return false
}

func (p *Property) RawValue() any {
	return p.Value
}

func (p *Property) AsRawStrings() ([]string, error) {
	if len(p.ctx.lines) < p.rng.GetEndLine() {
		return p.ctx.lines, nil
	}
	return p.ctx.lines[p.rng.GetStartLine()-1 : p.rng.GetEndLine()], nil
}

func (p *Property) resolveValue() (*Property, bool) {
	if !p.isFunction() || p.IsUnresolved() {
		return p, true
	}

	resolved, ok := ResolveIntrinsicFunc(p)
	if ok {
		return resolved, true
	}

	p.unresolved = true
	return p, false
}

func (p *Property) GetStringProperty(path string, defaultValue ...string) misscanTypes.StringValue {
	defVal := ""
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	if p.IsUnresolved() {
		return misscanTypes.StringUnresolvable(p.Metadata())
	}

	prop := p.GetProperty(path)
	if prop.IsNotString() {
		return p.StringDefault(defVal)
	}
	return prop.AsStringValue()
}

func (p *Property) StringDefault(defaultValue string) misscanTypes.StringValue {
	return misscanTypes.StringDefault(defaultValue, p.Metadata())
}

func (p *Property) GetBoolProperty(path string, defaultValue ...bool) misscanTypes.BoolValue {
	defVal := false
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	if p.IsUnresolved() {
		return misscanTypes.BoolUnresolvable(p.Metadata())
	}

	prop := p.GetProperty(path)

	if prop.isFunction() {
		prop, _ = prop.resolveValue()
	}

	if prop.IsNotBool() {
		return p.inferBool(prop, defVal)
	}
	return prop.AsBoolValue()
}

func (p *Property) GetIntProperty(path string, defaultValue ...int) misscanTypes.IntValue {
	defVal := 0
	if len(defaultValue) > 0 {
		defVal = defaultValue[0]
	}

	if p.IsUnresolved() {
		return misscanTypes.IntUnresolvable(p.Metadata())
	}

	prop := p.GetProperty(path)

	if prop.IsNotInt() {
		return p.IntDefault(defVal)
	}
	return prop.AsIntValue()
}

func (p *Property) BoolDefault(defaultValue bool) misscanTypes.BoolValue {
	return misscanTypes.BoolDefault(defaultValue, p.Metadata())
}

func (p *Property) IntDefault(defaultValue int) misscanTypes.IntValue {
	return misscanTypes.IntDefault(defaultValue, p.Metadata())
}

func (p *Property) GetProperty(path string) *Property {
	pathParts := strings.Split(path, ".")

	first := pathParts[0]
	property := p

	if p.isFunction() {
		property, _ = p.resolveValue()
	}

	if property.IsNotMap() {
		return nil
	}

	for n, p := range property.AsMap() {
		if n == first {
			property = p
			break
		}
	}

	if len(pathParts) == 1 || property == nil {
		return property
	}

	if nestedProperty := property.GetProperty(strings.Join(pathParts[1:], ".")); nestedProperty != nil {
		if nestedProperty.isFunction() {
			resolved, _ := nestedProperty.resolveValue()
			return resolved
		}
		return nestedProperty
	}

	return &Property{}
}

func (p *Property) deriveResolved(propType cftypes.CfType, propValue any) *Property {
	return &Property{
		Location:    p.Location,
		Value:       propValue,
		Type:        propType,
		ctx:         p.ctx,
		name:        p.name,
		comment:     p.comment,
		rng:         p.rng,
		parentRange: p.parentRange,
		logicalId:   p.logicalId,
	}
}

func (p *Property) ParentRange() misscanTypes.Range {
	return p.parentRange
}

func (p *Property) inferBool(prop *Property, defaultValue bool) misscanTypes.BoolValue {
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

	return p.BoolDefault(defaultValue)
}

func (p *Property) String() string {
	r := ""
	switch p.Type {
	case cftypes.String:
		r = p.AsString()
	case cftypes.Int:
		r = strconv.Itoa(p.AsInt())
	}
	return r
}

func (p *Property) setLogicalResource(id string) {
	p.logicalId = id

	if p.isFunction() {
		return
	}

	if p.IsMap() {
		for _, subProp := range p.AsMap() {
			if subProp == nil {
				continue
			}
			subProp.setLogicalResource(id)
		}
	}

	if p.IsList() {
		for _, subProp := range p.AsList() {
			subProp.setLogicalResource(id)
		}
	}
}

func (p *Property) GetJsonBytes(squashList ...bool) []byte {
	if p.IsNil() {
		return []byte{}
	}
	lines, err := p.AsRawStrings()
	if err != nil {
		return nil
	}
	if p.ctx.SourceFormat == JsonSourceFormat {
		return []byte(strings.Join(lines, " "))
	}

	if len(squashList) > 0 {
		lines[0] = strings.Replace(lines[0], "-", " ", 1)
	}

	lines = removeLeftMargin(lines)

	yamlContent := strings.Join(lines, "\n")
	var body any
	if err := yaml.Unmarshal([]byte(yamlContent), &body); err != nil {
		return nil
	}
	jsonBody := convert(body)
	policyJson, err := json.Marshal(jsonBody)
	if err != nil {
		return nil
	}
	return policyJson
}

func (p *Property) GetJsonBytesAsString(squashList ...bool) string {
	return string(p.GetJsonBytes(squashList...))
}

func removeLeftMargin(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	prefixSpace := len(lines[0]) - len(strings.TrimLeft(lines[0], " "))

	for i, line := range lines {
		if len(line) >= prefixSpace {
			lines[i] = line[prefixSpace:]
		}
	}
	return lines
}

func convert(input any) any {
	switch x := input.(type) {
	case map[any]any:
		outpMap := make(map[string]any)
		for k, v := range x {
			outpMap[k.(string)] = convert(v)
		}
		return outpMap
	case []any:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return input
}

func (p *Property) inferType() {
	typ := cftypes.TypeFromGoValue(p.Value)
	if typ == cftypes.Unknown {
		return
	}
	p.Type = typ
}
