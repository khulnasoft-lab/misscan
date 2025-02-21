package google

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/bigquery"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/compute"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/dns"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/kms"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google/storage"
)

type Google struct {
	BigQuery bigquery.BigQuery
	Compute  compute.Compute
	DNS      dns.DNS
	GKE      gke.GKE
	KMS      kms.KMS
	IAM      iam.IAM
	SQL      sql.SQL
	Storage  storage.Storage
}
