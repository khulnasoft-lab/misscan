package container

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/container"
	"github.com/khulnasoft-lab/misscan/pkg/scanners/azure"
)

func Adapt(deployment azure.Deployment) container.Container {
	return container.Container{
		KubernetesClusters: adaptKubernetesClusters(deployment),
	}
}

func adaptKubernetesClusters(_ azure.Deployment) []container.KubernetesCluster {

	return nil
}
