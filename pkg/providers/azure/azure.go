package azure

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/appservice"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/authorization"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/compute"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/container"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/database"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/datafactory"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/datalake"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/keyvault"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/monitor"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/network"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/securitycenter"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/storage"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure/synapse"
)

type Azure struct {
	AppService     appservice.AppService
	Authorization  authorization.Authorization
	Compute        compute.Compute
	Container      container.Container
	Database       database.Database
	DataFactory    datafactory.DataFactory
	DataLake       datalake.DataLake
	KeyVault       keyvault.KeyVault
	Monitor        monitor.Monitor
	Network        network.Network
	SecurityCenter securitycenter.SecurityCenter
	Storage        storage.Storage
	Synapse        synapse.Synapse
}
