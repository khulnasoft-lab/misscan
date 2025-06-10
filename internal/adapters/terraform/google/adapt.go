package google

import (
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/bigquery"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/compute"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/dns"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/gke"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/iam"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/kms"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/sql"
	"github.com/khulnasoft-lab/misscan/internal/adapters/terraform/google/storage"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
)

func Adapt(modules terraform.Modules) google.Google {
	return google.Google{
		BigQuery: bigquery.Adapt(modules),
		Compute:  compute.Adapt(modules),
		DNS:      dns.Adapt(modules),
		GKE:      gke.Adapt(modules),
		KMS:      kms.Adapt(modules),
		IAM:      iam.Adapt(modules),
		SQL:      sql.Adapt(modules),
		Storage:  storage.Adapt(modules),
	}
}
