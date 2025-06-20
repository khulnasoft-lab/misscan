package athena

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/athena"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/cloudformation/parser"
)

func getWorkGroups(cfFile parser.FileContext) []athena.Workgroup {

	var workgroups []athena.Workgroup

	workgroupResources := cfFile.GetResourcesByType("AWS::Athena::WorkGroup")

	for _, r := range workgroupResources {

		wg := athena.Workgroup{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("Name"),
			Encryption: athena.EncryptionConfiguration{
				Metadata: r.Metadata(),
				Type:     r.GetStringProperty("WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration.EncryptionOption"),
			},
			EnforceConfiguration: r.GetBoolProperty("WorkGroupConfiguration.EnforceWorkGroupConfiguration"),
		}

		workgroups = append(workgroups, wg)
	}

	return workgroups
}
