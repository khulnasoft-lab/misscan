package v1

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

type API struct {
	Metadata  misscanTypes.Metadata
	Name      misscanTypes.StringValue
	Stages    []Stage
	Resources []Resource
}

type Stage struct {
	Metadata           misscanTypes.Metadata
	Name               misscanTypes.StringValue
	AccessLogging      AccessLogging
	XRayTracingEnabled misscanTypes.BoolValue
	RESTMethodSettings []RESTMethodSettings
}

type Resource struct {
	Metadata misscanTypes.Metadata
	Methods  []Method
}

type AccessLogging struct {
	Metadata              misscanTypes.Metadata
	CloudwatchLogGroupARN misscanTypes.StringValue
}

type RESTMethodSettings struct {
	Metadata           misscanTypes.Metadata
	Method             misscanTypes.StringValue
	CacheDataEncrypted misscanTypes.BoolValue
	CacheEnabled       misscanTypes.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type Method struct {
	Metadata          misscanTypes.Metadata
	HTTPMethod        misscanTypes.StringValue
	AuthorizationType misscanTypes.StringValue
	APIKeyRequired    misscanTypes.BoolValue
}

type DomainName struct {
	Metadata       misscanTypes.Metadata
	Name           misscanTypes.StringValue
	SecurityPolicy misscanTypes.StringValue
}
