package v2

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

const (
	ProtocolTypeUnknown   string = ""
	ProtocolTypeREST      string = "REST"
	ProtocolTypeHTTP      string = "HTTP"
	ProtocolTypeWebsocket string = "WEBSOCKET"
)

type API struct {
	Metadata     misscanTypes.Metadata
	Name         misscanTypes.StringValue
	ProtocolType misscanTypes.StringValue
	Stages       []Stage
}

type Stage struct {
	Metadata      misscanTypes.Metadata
	Name          misscanTypes.StringValue
	AccessLogging AccessLogging
}

type AccessLogging struct {
	Metadata              misscanTypes.Metadata
	CloudwatchLogGroupARN misscanTypes.StringValue
}

type DomainName struct {
	Metadata       misscanTypes.Metadata
	Name           misscanTypes.StringValue
	SecurityPolicy misscanTypes.StringValue
}
