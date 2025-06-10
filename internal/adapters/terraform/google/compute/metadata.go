package compute

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/zclconf/go-cty/cty"
)

func adaptProjectMetadata(modules terraform.Modules) compute.ProjectMetadata {
	metadata := compute.ProjectMetadata{
		Metadata: misscanTypes.NewUnmanagedMetadata(),
		EnableOSLogin: misscanTypes.BoolUnresolvable(
			misscanTypes.NewUnmanagedMetadata(),
		),
	}
	for _, metadataBlock := range modules.GetResourcesByType("google_compute_project_metadata") {
		metadata.Metadata = metadataBlock.GetMetadata()
		if metadataAttr := metadataBlock.GetAttribute("metadata"); metadataAttr.IsNotNil() {
			if val := metadataAttr.MapValue("enable-oslogin"); val.Type() == cty.Bool {
				metadata.EnableOSLogin = misscanTypes.BoolExplicit(val.True(), metadataAttr.GetMetadata())
			}
		}
	}
	return metadata
}
