package sqs

import (
	"github.com/google/uuid"
	"github.com/khulnasoft-lab/misscan/pkg/adapters/terraform/aws/iam"
	iamp "github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sqs"
	"github.com/khulnasoft-lab/misscan/pkg/terraform"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
)

func Adapt(modules terraform.Modules) sqs.SQS {
	return sqs.SQS{
		Queues: (&adapter{
			modules: modules,
			queues:  make(map[string]sqs.Queue),
		}).adaptQueues(),
	}
}

type adapter struct {
	modules terraform.Modules
	queues  map[string]sqs.Queue
}

func (a *adapter) adaptQueues() []sqs.Queue {
	for _, resource := range a.modules.GetResourcesByType("aws_sqs_queue") {
		a.adaptQueue(resource)
	}

	for _, policyBlock := range a.modules.GetResourcesByType("aws_sqs_queue_policy") {

		policy := iamp.Policy{
			Metadata: policyBlock.GetMetadata(),
			Name:     misscanTypes.StringDefault("", policyBlock.GetMetadata()),
			Document: iamp.Document{
				Metadata: policyBlock.GetMetadata(),
			},
			Builtin: misscanTypes.Bool(false, policyBlock.GetMetadata()),
		}
		if attr := policyBlock.GetAttribute("policy"); attr.IsString() {
			dataBlock, err := a.modules.GetBlockById(attr.Value().AsString())
			if err != nil {
				policy.Document.Parsed = iamgo.Document{}
				policy.Document.Metadata = attr.GetMetadata()
			} else if dataBlock.Type() == "data" && dataBlock.TypeLabel() == "aws_iam_policy_document" { // nolint: goconst
				if doc, err := iam.ConvertTerraformDocument(a.modules, dataBlock); err == nil {
					policy.Document.Parsed = doc.Document
					policy.Document.Metadata = doc.Source.GetMetadata()
					policy.Document.IsOffset = true
				}
			}
		} else if refBlock, err := a.modules.GetReferencedBlock(attr, policyBlock); err == nil {
			if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" { // nolint: goconst
				if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
					policy.Document.Parsed = doc.Document
					policy.Document.Metadata = doc.Source.GetMetadata()
				}
			}
		}

		if urlAttr := policyBlock.GetAttribute("queue_url"); urlAttr.IsNotNil() {
			if refBlock, err := a.modules.GetReferencedBlock(urlAttr, policyBlock); err == nil {
				if queue, ok := a.queues[refBlock.ID()]; ok {
					queue.Policies = append(queue.Policies, policy)
					a.queues[refBlock.ID()] = queue
					continue
				}
			}
		}

		a.queues[uuid.NewString()] = sqs.Queue{
			Metadata: misscanTypes.NewUnmanagedMetadata(),
			QueueURL: misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			Encryption: sqs.Encryption{
				Metadata:          misscanTypes.NewUnmanagedMetadata(),
				ManagedEncryption: misscanTypes.BoolDefault(false, misscanTypes.NewUnmanagedMetadata()),
				KMSKeyID:          misscanTypes.StringDefault("", misscanTypes.NewUnmanagedMetadata()),
			},
			Policies: []iamp.Policy{policy},
		}
	}

	var queues []sqs.Queue
	for _, queue := range a.queues {
		queues = append(queues, queue)
	}
	return queues
}

func (a *adapter) adaptQueue(resource *terraform.Block) {

	kmsKeyIdAttr := resource.GetAttribute("kms_master_key_id")
	kmsKeyIdVal := kmsKeyIdAttr.AsStringValueOrDefault("", resource)
	managedEncryption := resource.GetAttribute("sqs_managed_sse_enabled")

	var policies []iamp.Policy
	if attr := resource.GetAttribute("policy"); attr.IsString() {

		dataBlock, err := a.modules.GetBlockById(attr.Value().AsString())
		if err != nil {
			policy := iamp.Policy{
				Metadata: attr.GetMetadata(),
				Name:     misscanTypes.StringDefault("", attr.GetMetadata()),
				Document: iamp.Document{
					Metadata: attr.GetMetadata(),
				},
				Builtin: misscanTypes.Bool(false, attr.GetMetadata()),
			}
			parsed, err := iamgo.ParseString(attr.Value().AsString())
			if err == nil {
				policy.Document.Parsed = *parsed
				policy.Document.Metadata = attr.GetMetadata()
				policy.Metadata = attr.GetMetadata()
				policies = append(policies, policy)
			}
		} else if dataBlock.Type() == "data" && dataBlock.TypeLabel() == "aws_iam_policy_document" {
			if doc, err := iam.ConvertTerraformDocument(a.modules, dataBlock); err == nil {
				policy := iamp.Policy{
					Metadata: attr.GetMetadata(),
					Name:     misscanTypes.StringDefault("", attr.GetMetadata()),
					Document: iamp.Document{
						Metadata: doc.Source.GetMetadata(),
						Parsed:   doc.Document,
						IsOffset: true,
						HasRefs:  false,
					},
					Builtin: misscanTypes.Bool(false, attr.GetMetadata()),
				}
				policies = append(policies, policy)
			}
		}

	} else if refBlock, err := a.modules.GetReferencedBlock(attr, resource); err == nil {
		if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
			if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
				policy := iamp.Policy{
					Metadata: doc.Source.GetMetadata(),
					Name:     misscanTypes.StringDefault("", doc.Source.GetMetadata()),
					Document: iamp.Document{
						Metadata: doc.Source.GetMetadata(),
						Parsed:   doc.Document,
					},
					Builtin: misscanTypes.Bool(false, refBlock.GetMetadata()),
				}
				policies = append(policies, policy)
			}
		}
	}

	a.queues[resource.ID()] = sqs.Queue{
		Metadata: resource.GetMetadata(),
		QueueURL: misscanTypes.StringDefault("", resource.GetMetadata()),
		Encryption: sqs.Encryption{
			Metadata:          resource.GetMetadata(),
			ManagedEncryption: managedEncryption.AsBoolValueOrDefault(false, resource),
			KMSKeyID:          kmsKeyIdVal,
		},
		Policies: policies,
	}
}
