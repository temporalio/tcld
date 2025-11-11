package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/temporalio/tcld/protogen/api/account/v1"
	"github.com/temporalio/tcld/protogen/api/accountservice/v1"
	cloudaccount "github.com/temporalio/tcld/protogen/api/cloud/account/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	cloudSink "github.com/temporalio/tcld/protogen/api/cloud/sink/v1"
	"github.com/temporalio/tcld/protogen/api/common/v1"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
)

const (
	auditLogSinkTypeFlagName     = "audit-log-sink-type"
	destinationUriFlagName       = "destination-uri"
	sinkServiceAccountIDFlagName = "service-account-id"
	topicNameFlagName            = "topic-name"
	roleNameFlagName             = "role-name"
	kinesisAuditLogSinkType      = "kinesis"
	pubsubAuditLogSinkType       = "pubsub"
)

var (
	destinationUriFlag = &cli.StringFlag{
		Name:     destinationUriFlagName,
		Usage:    "The destination URI of the audit log sink",
		Aliases:  []string{"du"},
		Required: true,
	}
	sinkServiceAccountIDFlag = &cli.StringFlag{
		Name:     sinkServiceAccountIDFlagName,
		Usage:    "The service account ID to impersonate to write to the sink",
		Aliases:  []string{"sai"},
		Required: true,
	}
	roleNameFlag = &cli.StringFlag{
		Name:     roleNameFlagName,
		Usage:    "The role name to use to write to the sink",
		Aliases:  []string{"rn"},
		Required: true,
	}
	topicNameFlag = &cli.StringFlag{
		Name:     topicNameFlagName,
		Usage:    "The topic name to write to the sink",
		Aliases:  []string{"tn"},
		Required: true,
	}
	gcpProjectIdFlag = &cli.StringFlag{
		Name:     gcpProjectIdFlagName,
		Usage:    "The GCP project ID to write to the sink",
		Aliases:  []string{"gpi"},
		Required: true,
	}
	sinkRegionFlagRequired = &cli.StringFlag{
		Name:     sinkRegionFlagName,
		Usage:    "The region to use for the request",
		Aliases:  []string{"re"},
		Required: true,
	}
)

type AccountClient struct {
	client         accountservice.AccountServiceClient
	cloudAPIClient cloudservice.CloudServiceClient
	ctx            context.Context
}

type regionInfo struct {
	CloudProviderRegion string
	CloudProvider       string
}

func NewAccountClient(ctx context.Context, conn *grpc.ClientConn) *AccountClient {
	return &AccountClient{
		client:         accountservice.NewAccountServiceClient(conn),
		cloudAPIClient: cloudservice.NewCloudServiceClient(conn),
		ctx:            ctx,
	}
}

type GetAccountClientFn func(ctx *cli.Context) (*AccountClient, error)

func GetAccountClient(ctx *cli.Context) (*AccountClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return NewAccountClient(ct, conn), nil
}

func (c *AccountClient) getAccount() (*account.Account, error) {
	res, err := c.client.GetAccount(c.ctx, &accountservice.GetAccountRequest{})
	if err != nil {
		return nil, err
	}

	if res.Account == nil || res.Account.GetSpec() == nil {
		// this should never happen, the server should return an error when the account is not found
		return nil, fmt.Errorf("invalid account returned by server")
	}

	return res.Account, nil
}

func (c *AccountClient) listRegions() ([]regionInfo, error) {
	resp, err := c.client.GetRegions(c.ctx, &accountservice.GetRegionsRequest{})
	if err != nil {
		return nil, fmt.Errorf("unable to get regions: %w", err)
	}

	var regions []regionInfo
	for _, r := range resp.Regions {
		regions = append(regions, regionInfo{
			CloudProviderRegion: r.GetRegionId().GetName(),
			CloudProvider:       strings.ToLower(strings.TrimPrefix(common.RegionID_CloudProvider_name[int32(r.GetRegionId().GetProvider())], "CloudProvider")),
		})
	}

	sort.SliceStable(regions, func(i, j int) bool {
		if regions[i].CloudProvider < regions[j].CloudProvider {
			return true
		}

		return regions[i].CloudProviderRegion < regions[j].CloudProviderRegion
	})

	return regions, nil
}

func (c *AccountClient) updateAccount(ctx *cli.Context, a *account.Account) error {
	resourceVersion := a.ResourceVersion
	if v := ctx.String(ResourceVersionFlagName); v != "" {
		resourceVersion = v
	}

	res, err := c.client.UpdateAccount(c.ctx, &accountservice.UpdateAccountRequest{
		RequestId:       ctx.String(RequestIDFlagName),
		ResourceVersion: resourceVersion,
		Spec:            a.Spec,
	})
	if err != nil {
		return err
	}

	return PrintProto(res)
}

func (c *AccountClient) parseExistingMetricsCerts(ctx *cli.Context) (account *account.Account, existing caCerts, err error) {
	a, err := c.getAccount()
	if err != nil {
		return nil, nil, err
	}

	var existingCerts caCerts
	if a.GetSpec().GetMetrics() != nil && a.GetSpec().GetMetrics().GetAcceptedClientCa() != "" {
		existingCerts, err = parseCertificates(a.GetSpec().GetMetrics().GetAcceptedClientCa())
		if err != nil {
			return nil, nil, err
		}
	}

	return a, existingCerts, nil
}

func toAuditLogSinkSpec(ctx *cli.Context, auditLogSinkType string) (*cloudaccount.AuditLogSinkSpec, error) {
	spec := &cloudaccount.AuditLogSinkSpec{
		Name:    ctx.String(sinkNameFlag.Name),
		Enabled: ctx.Bool(sinkEnabledFlag.Name),
	}
	switch auditLogSinkType {
	case kinesisAuditLogSinkType:
		{
			spec.SinkType = &cloudaccount.AuditLogSinkSpec_KinesisSink{
				KinesisSink: &cloudSink.KinesisSpec{
					RoleName:       ctx.String(roleNameFlag.Name),
					DestinationUri: ctx.String(destinationUriFlag.Name),
					Region:         ctx.String(sinkRegionFlagRequired.Name),
				},
			}
		}
	case pubsubAuditLogSinkType:
		{
			spec.SinkType = &cloudaccount.AuditLogSinkSpec_PubSubSink{
				PubSubSink: &cloudSink.PubSubSpec{
					ServiceAccountId: ctx.String(sinkServiceAccountIDFlag.Name),
					TopicName:        ctx.String(topicNameFlag.Name),
					GcpProjectId:     ctx.String(gcpProjectIdFlag.Name),
				},
			}
		}
	default:
		{
			return nil, fmt.Errorf("invalid audit log sink type: %s", auditLogSinkType)
		}
	}
	return spec, nil
}

func (c *AccountClient) createAuditLogSink(spec *cloudaccount.AuditLogSinkSpec) (*cloudservice.CreateAccountAuditLogSinkResponse, error) {
	createAuditLogSinkResp, err := c.cloudAPIClient.CreateAccountAuditLogSink(c.ctx, &cloudservice.CreateAccountAuditLogSinkRequest{
		Spec: spec,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create audit log sink: %v", err)
	}
	return createAuditLogSinkResp, nil
}

func (c *AccountClient) updateAuditLogSink(ctx *cli.Context, spec *cloudaccount.AuditLogSinkSpec, resourceVersion string) (*cloudservice.UpdateAccountAuditLogSinkResponse, error) {
	if resourceVersion == "" {
		getAuditLogSinkRes, err := c.cloudAPIClient.GetAccountAuditLogSink(c.ctx, &cloudservice.GetAccountAuditLogSinkRequest{
			Name: ctx.String(sinkNameFlag.Name),
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get audit log sink: %v", err)
		}
		resourceVersion = getAuditLogSinkRes.GetSink().GetResourceVersion()
	}

	updateAuditLogSinkRes, err := c.cloudAPIClient.UpdateAccountAuditLogSink(c.ctx, &cloudservice.UpdateAccountAuditLogSinkRequest{
		Spec:            spec,
		ResourceVersion: resourceVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to update audit log sink: %v", err)
	}
	return updateAuditLogSinkRes, nil
}

func (c *AccountClient) validateAuditLogSink(spec *cloudaccount.AuditLogSinkSpec) error {
	validateRequest := &cloudservice.ValidateAccountAuditLogSinkRequest{
		Spec: spec,
	}

	_, err := c.cloudAPIClient.ValidateAccountAuditLogSink(c.ctx, validateRequest)
	if err != nil {
		return fmt.Errorf("validation failed with error %v", err)
	}

	return nil
}

func NewAccountCommand(getAccountClientFn GetAccountClientFn) (CommandOut, error) {
	var c *AccountClient
	commandOut := CommandOut{
		Command: &cli.Command{
			Name:    "account",
			Aliases: []string{"a"},
			Usage:   "Account operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getAccountClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:    "get",
					Usage:   "Get account information",
					Aliases: []string{"g"},
					Action: func(ctx *cli.Context) error {
						n, err := c.getAccount()
						if err != nil {
							return err
						}
						return PrintProto(n)
					},
				},
				{
					Name:    "list-regions",
					Usage:   "Lists all regions where the account can provision namespaces",
					Aliases: []string{"l"},
					Action: func(ctx *cli.Context) error {
						regionInfos, err := c.listRegions()
						if err != nil {
							return err
						}
						return PrintObj(regionInfos)
					},
				},
				{
					Name:    "metrics",
					Usage:   "Configures the metrics endpoint for the Temporal Cloud Account",
					Aliases: []string{"m"},
					Subcommands: []*cli.Command{
						{
							Name:  "enable",
							Usage: "Enables the metrics endpoint. CA Certificates *must* be configured prior to enabling the endpoint",
							Action: func(ctx *cli.Context) error {
								a, err := c.getAccount()
								if err != nil {
									return err
								}

								if a.Spec.Metrics != nil && a.Spec.Metrics.Enabled {
									return errors.New("metrics endpoint is already enabled")
								}

								if a.Spec.Metrics == nil || a.Spec.Metrics.AcceptedClientCa == "" {
									return errors.New("metrics endpoint cannot be enabled until ca certificates have been configured")
								}

								a.Spec.Metrics.Enabled = true
								return c.updateAccount(ctx, a)
							},
						},
						{
							Name:  "disable",
							Usage: "Disables the metrics endpoint",
							Action: func(ctx *cli.Context) error {
								a, err := c.getAccount()
								if err != nil {
									return err
								}

								if a.Spec.Metrics == nil || !a.Spec.Metrics.Enabled {
									return errors.New("metrics endpoint is already disabled")
								}

								a.Spec.Metrics.Enabled = false
								return c.updateAccount(ctx, a)
							},
						},
						{
							Name:    "accepted-client-ca",
							Usage:   "Manages configuration of ca certificates for the external metrics endpoint",
							Aliases: []string{"ca"},
							Subcommands: []*cli.Command{
								{
									Name:    "add",
									Aliases: []string{"a"},
									Usage:   "Add a new ca accepted client ca certificate",
									Flags: []cli.Flag{
										RequestIDFlag,
										ResourceVersionFlag,
										CaCertificateFlag,
										CaCertificateFileFlag,
									},
									Action: func(ctx *cli.Context) error {
										newCerts, err := readAndParseCACerts(ctx)
										if err != nil {
											return err
										}

										a, existingCerts, err := c.parseExistingMetricsCerts(ctx)
										if err != nil {
											return err
										}

										existingCerts, err = addCerts(existingCerts, newCerts)
										if err != nil {
											return err
										}

										bundle, err := existingCerts.bundle()
										if err != nil {
											return err
										}

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa == bundle {
											return errors.New("nothing to change")
										}

										if a.Spec.Metrics == nil {
											a.Spec.Metrics = &account.MetricsSpec{}
										}

										a.Spec.Metrics.AcceptedClientCa = bundle
										return c.updateAccount(ctx, a)
									},
								},
								{
									Name:    "remove",
									Aliases: []string{"r"},
									Usage:   "Remove existing certificates",
									Flags: []cli.Flag{
										RequestIDFlag,
										ResourceVersionFlag,
										CaCertificateFlag,
										CaCertificateFileFlag,
										caCertificateFingerprintFlag,
									},
									Action: func(ctx *cli.Context) error {
										a, existingCerts, err := c.parseExistingMetricsCerts(ctx)
										if err != nil {
											return err
										}

										var certs caCerts
										if ctx.String(caCertificateFingerprintFlagName) != "" {
											certs, err = removeCertWithFingerprint(
												existingCerts,
												ctx.String(caCertificateFingerprintFlagName),
											)
											if err != nil {
												return err
											}
										} else {
											readCerts, err := readAndParseCACerts(ctx)
											if err != nil {
												return err
											}
											certs, err = removeCerts(existingCerts, readCerts)
											if err != nil {
												return err
											}
										}

										bundle, err := certs.bundle()
										if err != nil {
											return err
										}

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa == bundle {
											return errors.New("nothing to change")
										}

										if a.Spec.Metrics == nil {
											a.Spec.Metrics = &account.MetricsSpec{}
										}

										a.Spec.Metrics.AcceptedClientCa = bundle
										y, err := ConfirmPrompt(ctx, "removing ca certificates can cause connectivity disruption if there are any clients using certificates that cannot be verified. confirm remove?")
										if err != nil || !y {
											return err
										}
										return c.updateAccount(ctx, a)
									},
								},
								{
									Name:    "set",
									Aliases: []string{"s"},
									Usage:   "Set the accepted client ca certificate",
									Flags: []cli.Flag{
										RequestIDFlag,
										ResourceVersionFlag,
										CaCertificateFlag,
										CaCertificateFileFlag,
									},
									Action: func(ctx *cli.Context) error {
										cert, err := ReadCACerts(ctx)
										if err != nil {
											return err
										}

										a, err := c.getAccount()
										if err != nil {
											return err
										}

										fmt.Println("2: " + a.Spec.Metrics.AcceptedClientCa)

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa == cert {
											fmt.Printf("%+v vs %+v\r\n", cert, a.Spec.Metrics.AcceptedClientCa)
											return errors.New("nothing to change")
										}

										if a.Spec.Metrics == nil {
											a.Spec.Metrics = &account.MetricsSpec{}
										}
										a.Spec.Metrics.AcceptedClientCa = cert
										return c.updateAccount(ctx, a)
									},
								},
								{
									Name:    "list",
									Aliases: []string{"l"},
									Usage:   "List the accepted client ca certificates currently configured for the account metrics endpoint",
									Action: func(ctx *cli.Context) error {
										a, err := c.getAccount()
										if err != nil {
											return err
										}

										if a.Spec.Metrics != nil && a.Spec.Metrics.AcceptedClientCa != "" {
											out, err := parseCertificates(a.Spec.Metrics.AcceptedClientCa)
											if err != nil {
												return err
											}
											return PrintObj(out)
										}

										return PrintObj("no client ca certificates configured for metrics endpoint")
									},
								},
							},
						},
					},
				},
			},
		},
	}
	auditLogCommands := &cli.Command{
		Name:    "audit-log",
		Usage:   "audit log commands",
		Aliases: []string{"al"},
		Subcommands: []*cli.Command{
			{
				Name:    "sinks",
				Aliases: []string{"s"},
				Usage:   "Manage audit log sinks",
			},
		},
	}

	// Shared audit log sink commands (get, delete, list)
	auditLogGeneralCommands := []*cli.Command{
		{
			Name:    "get",
			Aliases: []string{"g"},
			Usage:   "Get audit log sink",
			Flags: []cli.Flag{
				sinkNameFlag,
			},
			Action: func(ctx *cli.Context) error {
				auditLogSinkRes, err := c.cloudAPIClient.GetAccountAuditLogSink(c.ctx, &cloudservice.GetAccountAuditLogSinkRequest{
					Name: ctx.String(sinkNameFlag.Name),
				})
				if err != nil {
					return fmt.Errorf("unable to get audit log sink: %v", err)
				}
				return PrintProto(auditLogSinkRes)
			},
		},
		{
			Name:    "delete",
			Aliases: []string{"d"},
			Usage:   "Delete audit log sink",
			Flags: []cli.Flag{
				sinkNameFlag,
				ResourceVersionFlag,
			},
			Action: func(ctx *cli.Context) error {
				sinkName := ctx.String(sinkNameFlag.Name)
				resourceVersion := ctx.String(ResourceVersionFlag.Name)

				if resourceVersion == "" {
					getAuditLogSinkRes, err := c.cloudAPIClient.GetAccountAuditLogSink(c.ctx, &cloudservice.GetAccountAuditLogSinkRequest{
						Name: sinkName,
					})
					if err != nil {
						return fmt.Errorf("unable to get audit log sink: %v", err)
					}
					resourceVersion = getAuditLogSinkRes.GetSink().GetResourceVersion()
				}

				deleteRequest := &cloudservice.DeleteAccountAuditLogSinkRequest{
					Name:            sinkName,
					ResourceVersion: resourceVersion,
				}

				deleteResp, err := c.cloudAPIClient.DeleteAccountAuditLogSink(c.ctx, deleteRequest)
				if err != nil {
					return err
				}
				return PrintProto(deleteResp.GetAsyncOperation())
			},
		},
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "List audit log sinks",
			Flags: []cli.Flag{
				pageSizeFlag,
				pageTokenFlag,
			},
			Action: func(ctx *cli.Context) error {
				request := &cloudservice.GetAccountAuditLogSinksRequest{
					PageSize:  int32(ctx.Int(pageSizeFlag.Name)),
					PageToken: ctx.String(pageTokenFlag.Name),
				}
				resp, err := c.cloudAPIClient.GetAccountAuditLogSinks(c.ctx, request)
				if err != nil {
					return err
				}
				return PrintProto(resp)
			},
		},
	}

	// Kinesis audit log sink commands
	kinesisAuditLogCommands := &cli.Command{
		Name:    "kinesis",
		Aliases: []string{"k"},
		Usage:   "Manage Kinesis audit log sink",
		Subcommands: []*cli.Command{
			{
				Name:    "create",
				Aliases: []string{"c"},
				Usage:   "Create a kinesis audit log sink",
				Flags: []cli.Flag{
					// general audit log sink flags
					sinkNameFlag,
					// kinesis audit log sink flags
					roleNameFlag,
					destinationUriFlag,
					sinkRegionFlagRequired,
				},
				Action: func(ctx *cli.Context) error {
					spec, err := toAuditLogSinkSpec(ctx, kinesisAuditLogSinkType)
					if err != nil {
						return err
					}
					spec.Enabled = true
					resp, err := c.createAuditLogSink(spec)
					if err != nil {
						return err
					}
					return PrintProto(resp)
				},
			},
			{
				Name:    "validate",
				Usage:   "Validate kinesis audit log sink",
				Aliases: []string{"v"},
				Flags: []cli.Flag{
					// general audit log sink flags
					sinkNameFlag,
					sinkEnabledFlag,
					// kinesis audit log sink flags
					roleNameFlag,
					destinationUriFlag,
					sinkRegionFlagRequired,
				},
				Action: func(ctx *cli.Context) error {
					spec, err := toAuditLogSinkSpec(ctx, kinesisAuditLogSinkType)
					if err != nil {
						return err
					}
					err = c.validateAuditLogSink(spec)
					if err != nil {
						return err
					}
					fmt.Println("Temporal Cloud was able to validate the sink")
					return nil
				},
			},
			{
				Name:    "update",
				Aliases: []string{"u"},
				Usage:   "Update a kinesis audit log sink",
				Flags: []cli.Flag{
					// general audit log sink flags
					sinkNameFlag,
					sinkEnabledFlag,
					ResourceVersionFlag,
					// kinesis audit log sink flags
					roleNameFlag,
					destinationUriFlag,
					sinkRegionFlagRequired,
				},
				Action: func(ctx *cli.Context) error {
					spec, err := toAuditLogSinkSpec(ctx, kinesisAuditLogSinkType)
					if err != nil {
						return err
					}
					resourceVersion := ctx.String(ResourceVersionFlag.Name)
					updateAuditLogSinkRes, err := c.updateAuditLogSink(ctx, spec, resourceVersion)
					if err != nil {
						return err
					}
					return PrintProto(updateAuditLogSinkRes)
				},
			},
		},
	}

	// PubSub audit log sink commands
	pubsubAuditLogCommands := &cli.Command{
		Name:    "pubsub",
		Aliases: []string{"ps"},
		Usage:   "Manage PubSub audit log sink",
		Subcommands: []*cli.Command{
			{
				Name:    "create",
				Aliases: []string{"c"},
				Usage:   "Create a pubsub audit log sink",
				Flags: []cli.Flag{
					// general audit log sink flags
					sinkNameFlag,
					// pubsub audit log sink flags
					sinkServiceAccountIDFlag,
					topicNameFlag,
					gcpProjectIdFlag,
				},
				Action: func(ctx *cli.Context) error {
					spec, err := toAuditLogSinkSpec(ctx, pubsubAuditLogSinkType)
					if err != nil {
						return err
					}
					spec.Enabled = true
					resp, err := c.createAuditLogSink(spec)
					if err != nil {
						return err
					}
					return PrintProto(resp)
				},
			},
			{
				Name:    "validate",
				Usage:   "Validate pubsub audit log sink",
				Aliases: []string{"v"},
				Flags: []cli.Flag{
					// general audit log sink flags
					sinkNameFlag,
					sinkEnabledFlag,
					// pubsub audit log sink flags
					sinkServiceAccountIDFlag,
					topicNameFlag,
					gcpProjectIdFlag,
				},
				Action: func(ctx *cli.Context) error {
					spec, err := toAuditLogSinkSpec(ctx, pubsubAuditLogSinkType)
					if err != nil {
						return err
					}
					err = c.validateAuditLogSink(spec)
					if err != nil {
						return err
					}
					fmt.Println("Temporal Cloud was able to validate the sink")
					return nil
				},
			},
			{
				Name:    "update",
				Aliases: []string{"u"},
				Usage:   "Update a pubsub audit log sink",
				Flags: []cli.Flag{
					// general audit log sink flags
					sinkNameFlag,
					sinkEnabledFlag,
					ResourceVersionFlag,
					// pubsub audit log sink flags
					sinkServiceAccountIDFlag,
					topicNameFlag,
					gcpProjectIdFlag,
				},
				Action: func(ctx *cli.Context) error {
					spec, err := toAuditLogSinkSpec(ctx, pubsubAuditLogSinkType)
					if err != nil {
						return err
					}
					resourceVersion := ctx.String(ResourceVersionFlag.Name)
					updateAuditLogSinkRes, err := c.updateAuditLogSink(ctx, spec, resourceVersion)
					if err != nil {
						return err
					}
					return PrintProto(updateAuditLogSinkRes)
				},
			},
		},
	}

	kinesisAuditLogCommands.Subcommands = append(kinesisAuditLogCommands.Subcommands, auditLogGeneralCommands...)
	pubsubAuditLogCommands.Subcommands = append(pubsubAuditLogCommands.Subcommands, auditLogGeneralCommands...)

	auditLogCommands.Subcommands[0].Subcommands = []*cli.Command{
		kinesisAuditLogCommands,
		pubsubAuditLogCommands,
	}
	if IsFeatureEnabled(AuditLogSinkNewAPIFeatureFlag) {
		commandOut.Command.Subcommands = append(commandOut.Command.Subcommands, auditLogCommands)
	}
	return commandOut, nil
}
