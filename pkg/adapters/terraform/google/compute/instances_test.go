package compute

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/internal/testutil"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []compute.Instance
	}{
		{
			name: "defined",
			terraform: `
			resource "google_service_account" "myaccount" {
			  }
		  
			resource "google_compute_instance" "example" {
				name         = "test"
		
				boot_disk {
					device_name = "boot-disk"
					kms_key_self_link = "something"
				  }
			  
				shielded_instance_config {
				  enable_integrity_monitoring = true
				  enable_vtpm = true
				  enable_secure_boot = true
				}

				network_interface {
					network = "default"
				
					access_config {
					}
				  }

				  service_account {
					email  = google_service_account.myaccount.email
					scopes = ["cloud-platform"]
				  }
				  can_ip_forward = true

				  metadata = {
					enable-oslogin = false
					block-project-ssh-keys = true
					serial-port-enable = true
				  }
			  }
`,
			expected: []compute.Instance{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("test", misscanTypes.NewTestMetadata()),
					NetworkInterfaces: []compute.NetworkInterface{
						{
							Metadata:    misscanTypes.NewTestMetadata(),
							HasPublicIP: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
							NATIP:       misscanTypes.String("", misscanTypes.NewTestMetadata()),
						},
					},
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   misscanTypes.NewTestMetadata(),
						SecureBootEnabled:          misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
						VTPMEnabled:                misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata: misscanTypes.NewTestMetadata(),
						Email:    misscanTypes.String("", misscanTypes.NewTestMetadata()),
						Scopes: []misscanTypes.StringValue{
							misscanTypes.String("cloud-platform", misscanTypes.NewTestMetadata()),
						},
						IsDefault: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
					CanIPForward:                misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					OSLoginEnabled:              misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					EnableSerialPort:            misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),

					BootDisks: []compute.Disk{
						{
							Metadata: misscanTypes.NewTestMetadata(),
							Name:     misscanTypes.String("boot-disk", misscanTypes.NewTestMetadata()),
							Encryption: compute.DiskEncryption{
								Metadata:   misscanTypes.NewTestMetadata(),
								KMSKeyLink: misscanTypes.String("something", misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_instance" "example" {
			  }
`,
			expected: []compute.Instance{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   misscanTypes.NewTestMetadata(),
						SecureBootEnabled:          misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						VTPMEnabled:                misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  misscanTypes.NewTestMetadata(),
						Email:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
						IsDefault: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
					CanIPForward:                misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					OSLoginEnabled:              misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					EnableSerialPort:            misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "default service account",
			terraform: `
			resource "google_compute_instance" "example" {
				service_account {}
			}
`,
			expected: []compute.Instance{
				{
					Metadata: misscanTypes.NewTestMetadata(),
					Name:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
					ShieldedVM: compute.ShieldedVMConfig{
						Metadata:                   misscanTypes.NewTestMetadata(),
						SecureBootEnabled:          misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						IntegrityMonitoringEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
						VTPMEnabled:                misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
					ServiceAccount: compute.ServiceAccount{
						Metadata:  misscanTypes.NewTestMetadata(),
						Email:     misscanTypes.String("", misscanTypes.NewTestMetadata()),
						IsDefault: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
					CanIPForward:                misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					OSLoginEnabled:              misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					EnableProjectSSHKeyBlocking: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					EnableSerialPort:            misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
