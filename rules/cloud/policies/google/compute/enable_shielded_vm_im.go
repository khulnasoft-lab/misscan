package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/rules"
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
)

var CheckEnableShieldedVMIntegrityMonitoring = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0045",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-shielded-vm-im",
		Summary:     "Instances should have Shielded VM integrity monitoring enabled",
		Impact:      "No visibility of VM instance boot state.",
		Resolution:  "Enable Shielded VM Integrity Monitoring",
		Explanation: `Integrity monitoring helps you understand and make decisions about the state of your VM instances.`,
		Links: []string{
			"https://cloud.google.com/security/shielded-cloud/shielded-vm#integrity-monitoring",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableShieldedVmImGoodExamples,
			BadExamples:         terraformEnableShieldedVmImBadExamples,
			Links:               terraformEnableShieldedVmImLinks,
			RemediationMarkdown: terraformEnableShieldedVmImRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.ShieldedVM.IntegrityMonitoringEnabled.IsFalse() {
				results.Add(
					"Instance does not have shielded VM integrity monitoring enabled.",
					instance.ShieldedVM.IntegrityMonitoringEnabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
