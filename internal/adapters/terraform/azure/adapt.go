package azure

import (
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/appservice"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/authorization"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/compute"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/container"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/database"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/datafactory"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/datalake"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/keyvault"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/monitor"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/network"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/securitycenter"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/storage"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/azure/synapse"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) azure.Azure {
	return azure.Azure{
		AppService:     appservice.Adapt(modules),
		Authorization:  authorization.Adapt(modules),
		Compute:        compute.Adapt(modules),
		Container:      container.Adapt(modules),
		Database:       database.Adapt(modules),
		DataFactory:    datafactory.Adapt(modules),
		DataLake:       datalake.Adapt(modules),
		KeyVault:       keyvault.Adapt(modules),
		Monitor:        monitor.Adapt(modules),
		Network:        network.Adapt(modules),
		SecurityCenter: securitycenter.Adapt(modules),
		Storage:        storage.Adapt(modules),
		Synapse:        synapse.Adapt(modules),
	}
}
