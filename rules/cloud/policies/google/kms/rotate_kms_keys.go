package kms

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckRotateKmsKeys = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0065",
		Provider:    providers.GoogleProvider,
		Service:     "kms",
		ShortCode:   "rotate-kms-keys",
		Summary:     "KMS keys should be rotated at least every 90 days",
		Impact:      "Exposure is greater if the same keys are used over a long period",
		Resolution:  "Set key rotation period to 90 days",
		Explanation: `Keys should be rotated on a regular basis to limit exposure if a given key should become compromised.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformRotateKmsKeysGoodExamples,
			BadExamples:         terraformRotateKmsKeysBadExamples,
			Links:               terraformRotateKmsKeysLinks,
			RemediationMarkdown: terraformRotateKmsKeysRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, keyring := range s.Google.KMS.KeyRings {
			for _, key := range keyring.Keys {
				if key.RotationPeriodSeconds.GreaterThan(7776000) {
					results.Add(
						"Key has a rotation period of more than 90 days.",
						key.RotationPeriodSeconds,
					)
				} else {
					results.AddPassed(&key)
				}
			}
		}
		return
	},
)
