package compute

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_adaptNetworks(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Network
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_subnetwork" "example" {
				name          = "test-subnetwork"
				network       = google_compute_network.example.id
				log_config {
				  aggregation_interval = "INTERVAL_10_MIN"
				  flow_sampling        = 0.5
				  metadata             = "INCLUDE_ALL_METADATA"
				}
			  }

			  resource "google_compute_network" "example" {
				name                    = "test-network"
				auto_create_subnetworks = false
			  }

			  resource "google_compute_firewall" "example" {
				name        = "my-firewall-rule"
				network = google_compute_network.example.name
				source_ranges = ["1.2.3.4/32"]
				allow {
				  protocol = "icmp"
				  ports     = ["80", "8080"]
				}
			  }
`,
			expected: []compute.Network{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("my-firewall-rule", misscanTypes.NewTestMetadata()),
						IngressRules: []compute.IngressRule{
							{
								Metadata: misscanTypes.NewTestMetadata(),
								FirewallRule: compute.FirewallRule{
									Metadata: misscanTypes.NewTestMetadata(),
									IsAllow:  misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
									Protocol: misscanTypes.String("icmp", misscanTypes.NewTestMetadata()),
									Enforced: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
									Ports: []misscanTypes.IntValue{
										misscanTypes.Int(80, misscanTypes.NewTestMetadata()),
										misscanTypes.Int(8080, misscanTypes.NewTestMetadata()),
									},
								},
								SourceRanges: []misscanTypes.StringValue{
									misscanTypes.String("1.2.3.4/32", misscanTypes.NewTestMetadata()),
								},
							},
						},
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       misscanTypes.NewTestMetadata(),
							Name:           misscanTypes.String("test-subnetwork", misscanTypes.NewTestMetadata()),
							EnableFlowLogs: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_subnetwork" "example" {
				network       = google_compute_network.example.id
			  }

			  resource "google_compute_network" "example" {
			  }

			  resource "google_compute_firewall" "example" {
				network = google_compute_network.example.name
			}
`,
			expected: []compute.Network{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Firewall: &compute.Firewall{
						Metadata: misscanTypes.NewTestMetadata(),
						Name:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
					},
					Subnetworks: []compute.SubNetwork{
						{
							Metadata:       misscanTypes.NewTestMetadata(),
							Name:           misscanTypes.String("", misscanTypes.NewTestMetadata()),
							EnableFlowLogs: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNetworks(modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
