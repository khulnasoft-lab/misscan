package apigateway

import (
	v1 "github.com/khulnasoft-lab/misscan/pkg/providers/aws/apigateway/v1"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func adaptDomainNamesV1(modules terraform.Modules) []v1.DomainName {

	var domainNames []v1.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_api_gateway_domain_name") {
			domainName := v1.DomainName{
				Metadata:       nameBlock.GetMetadata(),
				Name:           nameBlock.GetAttribute("domain_name").AsStringValueOrDefault("", nameBlock),
				SecurityPolicy: nameBlock.GetAttribute("security_policy").AsStringValueOrDefault("TLS_1_0", nameBlock),
			}
			domainNames = append(domainNames, domainName)
		}
	}

	return domainNames
}
