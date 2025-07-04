package parser

import (
	"encoding/base64"

	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/cftypes"
)

func ResolveBase64(property *Property) (*Property, bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Base64"].AsString()

	retVal := base64.StdEncoding.EncodeToString([]byte(refValue))

	return property.deriveResolved(cftypes.String, retVal), true
}
