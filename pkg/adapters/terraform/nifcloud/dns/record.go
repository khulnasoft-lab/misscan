package dns

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud/dns"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func adaptRecords(modules terraform.Modules) []dns.Record {
	var records []dns.Record

	for _, resource := range modules.GetResourcesByType("nifcloud_dns_record") {
		records = append(records, adaptRecord(resource))
	}
	return records
}

func adaptRecord(resource *terraform.Block) dns.Record {
	return dns.Record{
		Metadata: resource.GetMetadata(),
		Record:   resource.GetAttribute("record").AsStringValueOrDefault("", resource),
		Type:     resource.GetAttribute("type").AsStringValueOrDefault("", resource),
	}
}
