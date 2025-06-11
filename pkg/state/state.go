package state

import (
	"reflect"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws"
	"github.com/khulnasoft-lab/misscan/pkg/providers/azure"
	"github.com/khulnasoft-lab/misscan/pkg/providers/cloudstack"
	"github.com/khulnasoft-lab/misscan/pkg/providers/digitalocean"
	"github.com/khulnasoft-lab/misscan/pkg/providers/github"
	"github.com/khulnasoft-lab/misscan/pkg/providers/google"
	"github.com/khulnasoft-lab/misscan/pkg/providers/kubernetes"
	"github.com/khulnasoft-lab/misscan/pkg/providers/nifcloud"
	"github.com/khulnasoft-lab/misscan/pkg/providers/openstack"
	"github.com/khulnasoft-lab/misscan/pkg/providers/oracle"
	"github.com/khulnasoft-lab/misscan/pkg/rego/convert"
)

type State struct {
	AWS          aws.AWS
	Azure        azure.Azure
	CloudStack   cloudstack.CloudStack
	DigitalOcean digitalocean.DigitalOcean
	GitHub       github.GitHub
	Google       google.Google
	Kubernetes   kubernetes.Kubernetes
	OpenStack    openstack.OpenStack
	Oracle       oracle.Oracle
	Nifcloud     nifcloud.Nifcloud
}

func (a *State) ToRego() any {
	return convert.StructToRego(reflect.ValueOf(a))
}
