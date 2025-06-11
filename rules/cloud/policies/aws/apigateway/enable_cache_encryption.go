package apigateway

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableCacheEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0002",
		Provider:    providers.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-cache-encryption",
		Summary:     "API Gateway must have cache enabled",
		Impact:      "Data stored in the cache that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable cache encryption",
		Explanation: `Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableCacheEncryptionGoodExamples,
			BadExamples:         terraformEnableCacheEncryptionBadExamples,
			Links:               terraformEnableCacheEncryptionLinks,
			RemediationMarkdown: terraformEnableCacheEncryptionRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			if api.Metadata.IsUnmanaged() {
				continue
			}
			for _, stage := range api.Stages {
				if stage.Metadata.IsUnmanaged() {
					continue
				}
				for _, settings := range stage.RESTMethodSettings {
					if settings.Metadata.IsUnmanaged() {
						continue
					}
					if settings.CacheEnabled.IsFalse() {
						continue
					}
					if settings.CacheDataEncrypted.IsFalse() {
						results.Add(
							"Cache data is not encrypted.",
							settings.CacheDataEncrypted,
						)
					} else {
						results.AddPassed(&settings)
					}
				}
			}
		}
		return
	},
)
