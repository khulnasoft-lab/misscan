package dns

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/dns"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		ManagedZones: adaptManagedZones(modules),
	}
}

func adaptManagedZones(modules terraform.Modules) []dns.ManagedZone {
	var managedZones []dns.ManagedZone
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_dns_managed_zone") {
			managedZones = append(managedZones, adaptManagedZone(resource))
		}
	}
	return managedZones
}

func adaptManagedZone(resource *terraform.Block) dns.ManagedZone {
	zone := dns.ManagedZone{
		Metadata:   resource.GetMetadata(),
		Visibility: resource.GetAttribute("visibility").AsStringValueOrDefault("public", resource),
		DNSSec:     adaptDNSSec(resource),
	}
	return zone
}

func adaptDNSSec(b *terraform.Block) dns.DNSSec {
	DNSSecBlock := b.GetBlock("dnssec_config")
	if DNSSecBlock.IsNil() {
		return dns.DNSSec{
			Metadata: b.GetMetadata(),
			Enabled:  misscanTypes.BoolDefault(false, b.GetMetadata()),
		}
	}

	stateAttr := DNSSecBlock.GetAttribute("state")

	DNSSec := dns.DNSSec{
		Metadata:        DNSSecBlock.GetMetadata(),
		Enabled:         misscanTypes.Bool(stateAttr.Equals("on"), stateAttr.GetMetadata()),
		DefaultKeySpecs: adaptKeySpecs(DNSSecBlock),
	}

	return DNSSec
}

func adaptKeySpecs(b *terraform.Block) []dns.KeySpecs {
	var keySpecs []dns.KeySpecs
	for _, keySpecsBlock := range b.GetBlocks("default_key_specs") {
		keySpecs = append(keySpecs, dns.KeySpecs{
			Metadata:  keySpecsBlock.GetMetadata(),
			Algorithm: keySpecsBlock.GetAttribute("algorithm").AsStringValueOrDefault("", keySpecsBlock),
			KeyType:   keySpecsBlock.GetAttribute("key_type").AsStringValueOrDefault("", keySpecsBlock),
		})
	}
	return keySpecs
}
