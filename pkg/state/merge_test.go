package state

import (
	"testing"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws"
	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/rds"

	"github.com/stretchr/testify/assert"
)

func Test_Merging(t *testing.T) {
	tests := []struct {
		name           string
		a, b, expected State
	}{
		{
			name: "both empty",
		},
		{
			name: "a empty, b has a service",
			b: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
		},
		{
			name: "b empty, a has a service",
			a: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
		},
		{
			name: "both have differing versions of same service",
			a: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
			b: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever:B", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere:B", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere:B", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever:B", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere:B", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere:B", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
		},
		{
			name: "each has a different service",
			a: State{
				AWS: aws.AWS{
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
			b: State{
				AWS: aws.AWS{
					EC2: ec2.EC2{
						Instances: []ec2.Instance{
							{
								Metadata: misscanTypes.Metadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     misscanTypes.Metadata{},
									HttpTokens:   misscanTypes.String("something", misscanTypes.Metadata{}),
									HttpEndpoint: misscanTypes.String("something", misscanTypes.Metadata{}),
								},
								UserData: misscanTypes.String("something", misscanTypes.Metadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    misscanTypes.Metadata{},
										IsDefault:   misscanTypes.Bool(true, misscanTypes.Metadata{}),
										Description: misscanTypes.String("something", misscanTypes.Metadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    misscanTypes.Metadata{},
												Description: misscanTypes.String("something", misscanTypes.Metadata{}),
												CIDRs: []misscanTypes.StringValue{
													misscanTypes.String("something", misscanTypes.Metadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       misscanTypes.String("something", misscanTypes.Metadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  misscanTypes.Metadata{},
									Encrypted: misscanTypes.Bool(true, misscanTypes.Metadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  misscanTypes.Metadata{},
										Encrypted: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									},
								},
							},
						},
					},
				},
			},
			expected: State{
				AWS: aws.AWS{
					EC2: ec2.EC2{
						Instances: []ec2.Instance{
							{
								Metadata: misscanTypes.Metadata{},
								MetadataOptions: ec2.MetadataOptions{
									Metadata:     misscanTypes.Metadata{},
									HttpTokens:   misscanTypes.String("something", misscanTypes.Metadata{}),
									HttpEndpoint: misscanTypes.String("something", misscanTypes.Metadata{}),
								},
								UserData: misscanTypes.String("something", misscanTypes.Metadata{}),
								SecurityGroups: []ec2.SecurityGroup{
									{
										Metadata:    misscanTypes.Metadata{},
										IsDefault:   misscanTypes.Bool(true, misscanTypes.Metadata{}),
										Description: misscanTypes.String("something", misscanTypes.Metadata{}),
										IngressRules: []ec2.SecurityGroupRule{
											{
												Metadata:    misscanTypes.Metadata{},
												Description: misscanTypes.String("something", misscanTypes.Metadata{}),
												CIDRs: []misscanTypes.StringValue{
													misscanTypes.String("something", misscanTypes.Metadata{}),
												},
											},
										},
										EgressRules: nil,
										VPCID:       misscanTypes.String("something", misscanTypes.Metadata{}),
									},
								},
								RootBlockDevice: &ec2.BlockDevice{
									Metadata:  misscanTypes.Metadata{},
									Encrypted: misscanTypes.Bool(true, misscanTypes.Metadata{}),
								},
								EBSBlockDevices: []*ec2.BlockDevice{
									{
										Metadata:  misscanTypes.Metadata{},
										Encrypted: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									},
								},
							},
						},
					},
					RDS: rds.RDS{
						Instances: []rds.Instance{
							{
								BackupRetentionPeriodDays: misscanTypes.Int(1, misscanTypes.Metadata{}),
								ReplicationSourceARN:      misscanTypes.String("arn:whatever", misscanTypes.Metadata{}),
								PerformanceInsights: rds.PerformanceInsights{
									Metadata: misscanTypes.Metadata{},
									Enabled:  misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID: misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								Encryption: rds.Encryption{
									Metadata:       misscanTypes.Metadata{},
									EncryptStorage: misscanTypes.Bool(true, misscanTypes.Metadata{}),
									KMSKeyID:       misscanTypes.String("keyidhere", misscanTypes.Metadata{}),
								},
								PublicAccess: misscanTypes.Bool(true, misscanTypes.Metadata{}),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := test.a.Merge(&test.b)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, test.expected, *actual)
		})
	}

}
