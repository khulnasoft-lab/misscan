package appservice

import (
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

type AppService struct {
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	Metadata         misscanTypes.Metadata
	EnableClientCert misscanTypes.BoolValue
	Identity         struct {
		Type misscanTypes.StringValue
	}
	Authentication struct {
		Enabled misscanTypes.BoolValue
	}
	Site struct {
		EnableHTTP2       misscanTypes.BoolValue
		MinimumTLSVersion misscanTypes.StringValue
	}
}

type FunctionApp struct {
	Metadata  misscanTypes.Metadata
	HTTPSOnly misscanTypes.BoolValue
}
