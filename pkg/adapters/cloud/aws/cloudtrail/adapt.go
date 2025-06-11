package cloudtrail

import (
	"github.com/khulnasoft-lab/misscan/pkg/adapters/cloud/aws"
	"github.com/khulnasoft-lab/misscan/pkg/concurrency"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/cloudtrail"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

type adapter struct {
	*aws.RootAdapter
	client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "cloudtrail"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CloudTrail.Trails, err = a.getTrails()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getTrails() ([]cloudtrail.Trail, error) {

	a.Tracker().SetServiceLabel("Discovering trails...")

	var apiTrails []types.TrailInfo
	var input api.ListTrailsInput
	for {
		output, err := a.client.ListTrails(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiTrails = append(apiTrails, output.Trails...)
		a.Tracker().SetTotalResources(len(apiTrails))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting trails...")
	return concurrency.Adapt(apiTrails, a.RootAdapter, a.adaptTrail), nil
}

func (a *adapter) adaptTrail(info types.TrailInfo) (*cloudtrail.Trail, error) {

	metadata := a.CreateMetadataFromARN(*info.TrailARN)

	response, err := a.client.GetTrail(a.Context(), &api.GetTrailInput{
		Name: info.TrailARN,
	})
	if err != nil {
		return nil, err
	}

	var kmsKeyId string
	if response.Trail.KmsKeyId != nil {
		kmsKeyId = *response.Trail.KmsKeyId
	}

	status, err := a.client.GetTrailStatus(a.Context(), &api.GetTrailStatusInput{
		Name: response.Trail.Name,
	})
	if err != nil {
		return nil, err
	}

	cloudWatchLogsArn := misscanTypes.StringDefault("", metadata)
	if response.Trail.CloudWatchLogsLogGroupArn != nil {
		cloudWatchLogsArn = misscanTypes.String(*response.Trail.CloudWatchLogsLogGroupArn, metadata)
	}

	var bucketName string
	if response.Trail.S3BucketName != nil {
		bucketName = *response.Trail.S3BucketName
	}

	name := misscanTypes.StringDefault("", metadata)
	if info.Name != nil {
		name = misscanTypes.String(*info.Name, metadata)
	}

	isLogging := misscanTypes.BoolDefault(false, metadata)
	if status.IsLogging != nil {
		isLogging = misscanTypes.Bool(*status.IsLogging, metadata)
	}

	var eventSelectors []cloudtrail.EventSelector
	if response.Trail.HasCustomEventSelectors != nil && *response.Trail.HasCustomEventSelectors {
		output, err := a.client.GetEventSelectors(a.Context(), &api.GetEventSelectorsInput{
			TrailName: info.Name,
		})
		if err != nil {
			return nil, err
		}
		for _, eventSelector := range output.EventSelectors {
			var resources []cloudtrail.DataResource
			for _, dataResource := range eventSelector.DataResources {
				typ := misscanTypes.StringDefault("", metadata)
				if dataResource.Type != nil {
					typ = misscanTypes.String(*dataResource.Type, metadata)
				}
				var values misscanTypes.StringValueList
				for _, value := range dataResource.Values {
					values = append(values, misscanTypes.String(value, metadata))
				}
				resources = append(resources, cloudtrail.DataResource{
					Metadata: metadata,
					Type:     typ,
					Values:   values,
				})
			}
			eventSelectors = append(eventSelectors, cloudtrail.EventSelector{
				Metadata:      metadata,
				DataResources: resources,
				ReadWriteType: misscanTypes.String(string(eventSelector.ReadWriteType), metadata),
			})
		}
	}

	return &cloudtrail.Trail{
		Metadata:                  metadata,
		Name:                      name,
		EnableLogFileValidation:   misscanTypes.Bool(response.Trail.LogFileValidationEnabled != nil && *response.Trail.LogFileValidationEnabled, metadata),
		IsMultiRegion:             misscanTypes.Bool(response.Trail.IsMultiRegionTrail != nil && *response.Trail.IsMultiRegionTrail, metadata),
		CloudWatchLogsLogGroupArn: cloudWatchLogsArn,
		KMSKeyID:                  misscanTypes.String(kmsKeyId, metadata),
		IsLogging:                 isLogging,
		BucketName:                misscanTypes.String(bucketName, metadata),
		EventSelectors:            eventSelectors,
	}, nil
}
