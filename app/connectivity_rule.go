package app

import (
	"context"
	"fmt"

	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/connectivityrule/v1"
	regionpb "github.com/temporalio/tcld/protogen/api/cloud/region/v1"
	"github.com/temporalio/tcld/protogen/api/common/v1"
	"github.com/urfave/cli/v2"
)

const (
	connectionIdFlagName        = "connection-id"
	connectivityTypeFlagName    = "connectivity-type"
	regionFlagName              = "region"
	gcpProjectIdFlagName        = "gcp-project-id"
	connectivityRuleIdFlagName  = "connectivity-rule-id"
	connectivityRuleIdsFlagName = "connectivity-rule-ids"
)

type (
	ConnectivityRuleClient struct {
		client cloudservice.CloudServiceClient
		ctx    context.Context
	}
	GetConnectivityRuleClientFn func(ctx *cli.Context) (*ConnectivityRuleClient, error)
)

func GetConnectivityRuleClient(ctx *cli.Context) (*ConnectivityRuleClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &ConnectivityRuleClient{
		client: cloudservice.NewCloudServiceClient(conn),
		ctx:    ct,
	}, nil
}

func (c *ConnectivityRuleClient) getConnectivityRule(connectivityRuleId string) (*cloudservice.GetConnectivityRuleResponse, error) {
	resp, err := c.client.GetConnectivityRule(c.ctx, &cloudservice.GetConnectivityRuleRequest{
		ConnectivityRuleId: connectivityRuleId,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *ConnectivityRuleClient) createConnectivityRule(connectivityType, connectionId, region, gcpProjectId string, cloudProvider regionpb.Region_CloudProvider) (*cloudservice.CreateConnectivityRuleResponse, error) {
	spec := connectivityrule.ConnectivityRuleSpec{}
	switch connectivityType {
	case "private":
		spec = connectivityrule.ConnectivityRuleSpec{
			ConnectionType: &connectivityrule.ConnectivityRuleSpec_PrivateRule{
				PrivateRule: &connectivityrule.PrivateConnectivityRule{
					ConnectionId: connectionId,
					Region:       region,
					GcpProjectId: gcpProjectId,
				},
			},
		}
	case "public":
		spec = connectivityrule.ConnectivityRuleSpec{
			ConnectionType: &connectivityrule.ConnectivityRuleSpec_PublicRule{
				PublicRule: &connectivityrule.PublicConnectivityRule{},
			},
		}
	default:
		return nil, fmt.Errorf("unknown connectivity type: %s. only supports 'public' and 'private'", connectivityType)
	}

	return c.client.CreateConnectivityRule(c.ctx, &cloudservice.CreateConnectivityRuleRequest{
		Spec: &spec,
	})
}

func NewConnectivityRuleCommand(getConnectivityRuleClientFn GetConnectivityRuleClientFn) (CommandOut, error) {
	var c *ConnectivityRuleClient

	connectionIdFlag := &cli.StringFlag{
		Name:     connectionIdFlagName,
		Aliases:  []string{"ci"},
		Usage:    "The connection ID of the private connection",
		Required: false,
	}
	connectivityTypeFlag := &cli.StringFlag{
		Name:     connectivityTypeFlagName,
		Aliases:  []string{"ct"},
		Usage:    "The type of connectivity, currently only support 'private' and 'public'",
		Required: true,
	}
	regionFlag := &cli.StringFlag{
		Name:     regionFlagName,
		Aliases:  []string{"r"},
		Usage:    "The region of the connection",
		Required: false,
	}
	gcpProjectIdFlag := &cli.StringFlag{
		Name:     gcpProjectIdFlagName,
		Aliases:  []string{"gpi"},
		Usage:    "The GCP project ID of the connection, required if the cloud provider is 'gcp'",
		Required: false,
	}
	connectivityRuleIdFlag := &cli.StringFlag{
		Name:     connectivityRuleIdFlagName,
		Aliases:  []string{"id"},
		Usage:    "The connectivity rule ID",
		Required: true,
	}
	OptionalNamespaceFlag := &cli.StringFlag{
		Name:     NamespaceFlagName,
		Usage:    "The namespace hosted on temporal cloud",
		Aliases:  []string{"n"},
		EnvVars:  []string{"TEMPORAL_CLOUD_NAMESPACE"},
		Required: false,
	}

	if !IsFeatureEnabled(ConnectivityRuleFeatureFlag) {
		return CommandOut{
			Command: nil,
		}, nil
	}

	return CommandOut{
		Command: &cli.Command{
			Name:    "connectivity-rule",
			Aliases: []string{"cr"},
			Usage:   "Connectivity rule operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getConnectivityRuleClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:        "create",
					Aliases:     []string{"c"},
					Usage:       "Create a connectivity rule",
					Description: "This command creates a connectivity rule",
					Flags: []cli.Flag{
						connectivityTypeFlag,
						connectionIdFlag,
						regionFlag,
						gcpProjectIdFlag,
					},
					Action: func(ctx *cli.Context) error {
						provider, gcpProjectID, err := validateParamAndConvert(
							ctx.String(connectivityTypeFlagName),
							ctx.String(connectionIdFlagName),
							ctx.String(regionFlagName),
							ctx.String(gcpProjectIdFlagName))
						if err != nil {
							return err
						}

						resp, err := c.createConnectivityRule(
							ctx.String(connectivityTypeFlagName),
							ctx.String(connectionIdFlagName),
							ctx.String(regionFlagName),
							gcpProjectID,
							provider)
						if err != nil {
							return err
						}
						return PrintProto(resp)
					},
				},
				{
					Name:        "get",
					Aliases:     []string{"g"},
					Usage:       "Get a connectivity rule",
					Description: "This command gets a connectivity rule",
					Flags: []cli.Flag{
						connectivityRuleIdFlag,
					},
					Action: func(ctx *cli.Context) error {
						resp, err := c.getConnectivityRule(ctx.String(connectivityRuleIdFlagName))
						if err != nil {
							return err
						}
						return PrintProto(resp)
					},
				},
				{
					Name:        "list",
					Aliases:     []string{"l"},
					Usage:       "list connectivity rules",
					Description: "This command lists connectivity rules",
					Flags: []cli.Flag{
						OptionalNamespaceFlag,
					},
					Action: func(ctx *cli.Context) error {
						resp, err := c.client.GetConnectivityRules(c.ctx, &cloudservice.GetConnectivityRulesRequest{
							Namespace: ctx.String(NamespaceFlagName),
						})
						if err != nil {
							return err
						}
						return PrintProto(resp)
					},
				},
				{
					Name:        "delete",
					Aliases:     []string{"d"},
					Usage:       "Delete a connectivity rule",
					Description: "This command deletes a connectivity rule",
					Flags: []cli.Flag{
						connectivityRuleIdFlag,
					},
					Action: func(ctx *cli.Context) error {
						if _, err := c.getConnectivityRule(ctx.String(connectivityRuleIdFlagName)); err != nil {
							return fmt.Errorf("failed to get connectivity rule: %w", err)
						}

						resp, err := c.client.DeleteConnectivityRule(c.ctx, &cloudservice.DeleteConnectivityRuleRequest{
							ConnectivityRuleId: ctx.String(connectivityRuleIdFlagName),
						})
						if err != nil {
							return err
						}
						return PrintProto(resp)
					},
				},
			},
		},
	}, nil
}

func validateParamAndConvert(connectivityType, connectionId, region, gcpProjectId string) (regionpb.Region_CloudProvider, string, error) {
	switch connectivityType {
	case "private":
		if connectionId == "" {
			return regionpb.CLOUD_PROVIDER_UNSPECIFIED, "", fmt.Errorf("must provide connection id for private connectivity rule")
		}
		if region == "" {
			return regionpb.CLOUD_PROVIDER_UNSPECIFIED, "", fmt.Errorf("must provide region for private connectivity rule")
		}
		regionID, err := regionIDFromString(region)
		if err != nil {
			return regionpb.CLOUD_PROVIDER_UNSPECIFIED, "", fmt.Errorf("invalid region: %w", err)
		}

		var cp regionpb.Region_CloudProvider
		switch regionID.Provider {
		case common.CLOUD_PROVIDER_AWS:
			cp = regionpb.CLOUD_PROVIDER_AWS
		case common.CLOUD_PROVIDER_GCP:
			if gcpProjectId == "" {
				return regionpb.CLOUD_PROVIDER_UNSPECIFIED, "", fmt.Errorf("gcp project ID is required if the cloud provider is 'gcp'")
			}
			cp = regionpb.CLOUD_PROVIDER_GCP
		default:
			return regionpb.CLOUD_PROVIDER_UNSPECIFIED, "", fmt.Errorf("unknown or unsupported cloud provider in region: %s", region)
		}
		return cp, gcpProjectId, nil
	case "public":
		return regionpb.CLOUD_PROVIDER_UNSPECIFIED, "", nil
	default:
		return regionpb.CLOUD_PROVIDER_UNSPECIFIED, "", fmt.Errorf("unknown connectivity type: %s. only supports 'public' and 'private'", connectivityType)
	}
}
