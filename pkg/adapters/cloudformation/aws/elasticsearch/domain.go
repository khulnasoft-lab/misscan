package elasticsearch

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/elasticsearch"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func getDomains(ctx parser.FileContext) (domains []elasticsearch.Domain) {

	domainResources := ctx.GetResourcesByType("AWS::Elasticsearch::Domain", "AWS::OpenSearchService::Domain")

	for _, r := range domainResources {

		domain := elasticsearch.Domain{
			Metadata:       r.Metadata(),
			DomainName:     r.GetStringProperty("DomainName"),
			AccessPolicies: r.GetStringProperty("AccessPolicies"),
			VpcId:          misscanTypes.String("", r.Metadata()),
			LogPublishing: elasticsearch.LogPublishing{
				Metadata:              r.Metadata(),
				AuditEnabled:          misscanTypes.BoolDefault(false, r.Metadata()),
				CloudWatchLogGroupArn: misscanTypes.String("", r.Metadata()),
			},
			TransitEncryption: elasticsearch.TransitEncryption{
				Metadata: r.Metadata(),
				Enabled:  misscanTypes.BoolDefault(false, r.Metadata()),
			},
			AtRestEncryption: elasticsearch.AtRestEncryption{
				Metadata: r.Metadata(),
				Enabled:  misscanTypes.BoolDefault(false, r.Metadata()),
				KmsKeyId: misscanTypes.String("", r.Metadata()),
			},
			Endpoint: elasticsearch.Endpoint{
				Metadata:     r.Metadata(),
				EnforceHTTPS: misscanTypes.BoolDefault(false, r.Metadata()),
			},
			ServiceSoftwareOptions: elasticsearch.ServiceSoftwareOptions{
				Metadata:        r.Metadata(),
				CurrentVersion:  misscanTypes.String("", r.Metadata()),
				NewVersion:      misscanTypes.String("", r.Metadata()),
				UpdateStatus:    misscanTypes.String("", r.Metadata()),
				UpdateAvailable: misscanTypes.Bool(false, r.Metadata()),
			},
		}

		if r.Type() == "AWS::OpenSearchService::Domain" {
			domain.DedicatedMasterEnabled = r.GetBoolProperty("ClusterConfig.DedicatedMasterEnabled")
		} else {
			domain.DedicatedMasterEnabled = r.GetBoolProperty("ElasticsearchClusterConfig.DedicatedMasterEnabled")
		}

		if prop := r.GetProperty("LogPublishingOptions"); prop.IsNotNil() {
			domain.LogPublishing = elasticsearch.LogPublishing{
				Metadata:              prop.Metadata(),
				AuditEnabled:          prop.GetBoolProperty("AUDIT_LOGS.Enabled"),
				CloudWatchLogGroupArn: prop.GetStringProperty("AUDIT_LOGS.CloudWatchLogsLogGroupArn"),
			}
		}

		if prop := r.GetProperty("NodeToNodeEncryptionOptions"); prop.IsNotNil() {
			domain.TransitEncryption = elasticsearch.TransitEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled"),
			}
		}

		if prop := r.GetProperty("EncryptionAtRestOptions"); prop.IsNotNil() {
			domain.AtRestEncryption = elasticsearch.AtRestEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled"),
				KmsKeyId: prop.GetStringProperty("KmsKeyId"),
			}
		}

		if prop := r.GetProperty("DomainEndpointOptions"); prop.IsNotNil() {
			domain.Endpoint = elasticsearch.Endpoint{
				Metadata:     prop.Metadata(),
				EnforceHTTPS: prop.GetBoolProperty("EnforceHTTPS"),
				TLSPolicy:    prop.GetStringProperty("TLSSecurityPolicy"),
			}
		}

		domains = append(domains, domain)
	}

	return domains
}
