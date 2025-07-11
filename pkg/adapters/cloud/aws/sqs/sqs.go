package sqs

import (
	aws2 "github.com/khulnasoft-lab/misscan/pkg/adapters/cloud/aws"
	"github.com/khulnasoft-lab/misscan/pkg/concurrency"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/sqs"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	sqsApi "github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/khulnasoft-lab/iamgo"
)

type adapter struct {
	*aws2.RootAdapter
	client *sqsApi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "sqs"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = sqsApi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SQS.Queues, err = a.getQueues()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getQueues() (queues []sqs.Queue, err error) {

	a.Tracker().SetServiceLabel("Discovering SQS queues...")
	var apiQueueURLs []string
	var input sqsApi.ListQueuesInput

	for {
		output, err := a.client.ListQueues(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiQueueURLs = append(apiQueueURLs, output.QueueUrls...)
		a.Tracker().SetTotalResources(len(apiQueueURLs))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting SQS queues...")
	return concurrency.Adapt(apiQueueURLs, a.RootAdapter, a.adaptQueue), nil

}

func (a *adapter) adaptQueue(queueUrl string) (*sqs.Queue, error) {

	// make another call to get the attributes for the Queue
	queueAttributes, err := a.client.GetQueueAttributes(a.Context(), &sqsApi.GetQueueAttributesInput{
		QueueUrl: aws.String(queueUrl),
		AttributeNames: []sqsTypes.QueueAttributeName{
			sqsTypes.QueueAttributeNameSqsManagedSseEnabled,
			sqsTypes.QueueAttributeNameKmsMasterKeyId,
			sqsTypes.QueueAttributeNamePolicy,
			sqsTypes.QueueAttributeNameQueueArn,
		},
	})
	if err != nil {
		return nil, err
	}

	queueARN := queueAttributes.Attributes[string(sqsTypes.QueueAttributeNameQueueArn)]
	queueMetadata := a.CreateMetadataFromARN(queueARN)

	queue := &sqs.Queue{
		Metadata: queueMetadata,
		QueueURL: misscanTypes.String(queueUrl, queueMetadata),
		Policies: []iam.Policy{},
		Encryption: sqs.Encryption{
			Metadata:          queueMetadata,
			KMSKeyID:          misscanTypes.StringDefault("", queueMetadata),
			ManagedEncryption: misscanTypes.BoolDefault(false, queueMetadata),
		},
	}

	sseEncrypted := queueAttributes.Attributes[string(sqsTypes.QueueAttributeNameSqsManagedSseEnabled)]
	kmsEncryption := queueAttributes.Attributes[string(sqsTypes.QueueAttributeNameKmsMasterKeyId)]
	queuePolicy := queueAttributes.Attributes[string(sqsTypes.QueueAttributeNamePolicy)]

	if sseEncrypted == "SSE-SQS" || sseEncrypted == "SSE-KMS" {
		queue.Encryption.ManagedEncryption = misscanTypes.Bool(true, queueMetadata)
	}

	if kmsEncryption != "" {
		queue.Encryption.KMSKeyID = misscanTypes.String(kmsEncryption, queueMetadata)
	}

	if queuePolicy != "" {
		policy, err := iamgo.ParseString(queuePolicy)
		if err == nil {

			queue.Policies = append(queue.Policies, iam.Policy{
				Metadata: queueMetadata,
				Name:     misscanTypes.StringDefault("", queueMetadata),
				Document: iam.Document{
					Metadata: queueMetadata,
					Parsed:   *policy,
				},
				Builtin: misscanTypes.Bool(false, queueMetadata),
			})

		}

	}
	return queue, nil

}
