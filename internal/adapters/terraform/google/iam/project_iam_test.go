package iam

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"

	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/tftestutil"
	"github.com/khulnasoft-lab/misscan/test/testutil"
)

func Test_AdaptBinding(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iam.Binding
	}{
		{
			name: "defined",
			terraform: `
		resource "google_organization_iam_binding" "binding" {
			org_id = data.google_organization.org.id
			role    = "roles/browser"
			
			members = [
				"user:alice@gmail.com",
			]
		}`,
			expected: iam.Binding{
				Metadata: misscanTypes.NewTestMetadata(),
				Members: []misscanTypes.StringValue{
					misscanTypes.String("user:alice@gmail.com", misscanTypes.NewTestMetadata())},
				Role:                          misscanTypes.String("roles/browser", misscanTypes.NewTestMetadata()),
				IncludesDefaultServiceAccount: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
		resource "google_organization_iam_binding" "binding" {
		}`,
			expected: iam.Binding{
				Metadata:                      misscanTypes.NewTestMetadata(),
				Role:                          misscanTypes.String("", misscanTypes.NewTestMetadata()),
				IncludesDefaultServiceAccount: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := AdaptBinding(modules.GetBlocks()[0], modules)
			testutil.AssertMisscanEqual(t, test.expected, adapted)
		})
	}
}
