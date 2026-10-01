package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/clusterlink/v1"
	"github.com/urfave/cli/v2"
)

const (
	clusterLinkIDFlagName                   = "cluster-link-id"
	clusterLinkDisplayNameFlagName          = "display-name"
	clusterLinkRegionFlagName               = "region"
	clusterLinkAcceptedClientCAFileFlagName = "accepted-client-ca-file"
	clusterLinkConnectionStateFlagName      = "connection-state"
	clusterLinkPageSizeFlagName             = "page-size"
	clusterLinkPageTokenFlagName            = "page-token"
)

type (
	ClusterLinkClient struct {
		client cloudservice.CloudServiceClient
		ctx    context.Context
	}
	GetClusterLinkClientFn func(ctx *cli.Context) (*ClusterLinkClient, error)
)

func GetClusterLinkClient(ctx *cli.Context) (*ClusterLinkClient, error) {
	requestContext, connection, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &ClusterLinkClient{
		client: cloudservice.NewCloudServiceClient(connection),
		ctx:    requestContext,
	}, nil
}

func (c *ClusterLinkClient) get(clusterLinkID string) (*clusterlink.ClusterLink, error) {
	response, err := c.client.GetClusterLink(c.ctx, &cloudservice.GetClusterLinkRequest{
		ClusterLinkId: clusterLinkID,
	})
	if err != nil {
		return nil, err
	}
	return response.GetClusterLink(), nil
}

func (c *ClusterLinkClient) list(
	region string,
	states []clusterlink.ClusterLink_ConnectionState,
	pageSize int,
	pageToken string,
) (*cloudservice.GetClusterLinksResponse, error) {
	return c.client.GetClusterLinks(c.ctx, &cloudservice.GetClusterLinksRequest{
		PageSize:         int32(pageSize),
		PageToken:        pageToken,
		Region:           region,
		ConnectionStates: states,
	})
}

func (c *ClusterLinkClient) create(
	displayName string,
	region string,
	acceptedClientCA []byte,
	requestID string,
) (*cloudservice.CreateClusterLinkResponse, error) {
	return c.client.CreateClusterLink(c.ctx, &cloudservice.CreateClusterLinkRequest{
		Spec: &clusterlink.ClusterLinkSpec{
			DesiredConnectionState: clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
			DisplayName:            displayName,
			Region:                 region,
			Endpoint: &clusterlink.ClusterLinkEndpointSpec{
				Type: clusterlink.ENDPOINT_TYPE_PUBLIC_DNS,
				Security: &clusterlink.ClusterLinkEndpointSecuritySpec{
					AcceptedClientCa: acceptedClientCA,
				},
			},
		},
		AsyncOperationId: requestID,
	})
}

func (c *ClusterLinkClient) update(
	clusterLinkID string,
	resourceVersion string,
	requestID string,
	mutate func(*clusterlink.ClusterLinkSpec) error,
) (*cloudservice.UpdateClusterLinkResponse, error) {
	stored, err := c.get(clusterLinkID)
	if err != nil {
		return nil, err
	}
	if stored.GetSpec() == nil {
		return nil, fmt.Errorf("cluster link %q has no specification", clusterLinkID)
	}

	spec := proto.Clone(stored.GetSpec()).(*clusterlink.ClusterLinkSpec)
	if err := mutate(spec); err != nil {
		return nil, err
	}
	if resourceVersion == "" {
		resourceVersion = stored.GetResourceVersion()
	}
	return c.client.UpdateClusterLink(c.ctx, &cloudservice.UpdateClusterLinkRequest{
		ClusterLinkId:    clusterLinkID,
		Spec:             spec,
		ResourceVersion:  resourceVersion,
		AsyncOperationId: requestID,
	})
}

func (c *ClusterLinkClient) delete(
	clusterLinkID string,
	resourceVersion string,
	requestID string,
) (*cloudservice.DeleteClusterLinkResponse, error) {
	if resourceVersion == "" {
		stored, err := c.get(clusterLinkID)
		if err != nil {
			return nil, err
		}
		resourceVersion = stored.GetResourceVersion()
	}
	return c.client.DeleteClusterLink(c.ctx, &cloudservice.DeleteClusterLinkRequest{
		ClusterLinkId:    clusterLinkID,
		ResourceVersion:  resourceVersion,
		AsyncOperationId: requestID,
	})
}

func parseClusterLinkConnectionStates(values []string) ([]clusterlink.ClusterLink_ConnectionState, error) {
	if len(values) == 0 {
		return nil, nil
	}

	states := make([]clusterlink.ClusterLink_ConnectionState, 0, len(values))
	for _, value := range values {
		var state clusterlink.ClusterLink_ConnectionState
		switch strings.ToLower(strings.ReplaceAll(value, "_", "-")) {
		case "disconnected":
			state = clusterlink.CONNECTION_STATE_DISCONNECTED
		case "connecting":
			state = clusterlink.CONNECTION_STATE_CONNECTING
		case "connected":
			state = clusterlink.CONNECTION_STATE_CONNECTED
		case "connect-failed":
			state = clusterlink.CONNECTION_STATE_CONNECT_FAILED
		case "disconnecting":
			state = clusterlink.CONNECTION_STATE_DISCONNECTING
		case "disconnect-failed":
			state = clusterlink.CONNECTION_STATE_DISCONNECT_FAILED
		default:
			return nil, fmt.Errorf("invalid Cluster Link connection state %q", value)
		}
		states = append(states, state)
	}
	return states, nil
}

func NewClusterLinkCommand(getClusterLinkClient GetClusterLinkClientFn) (CommandOut, error) {
	var client *ClusterLinkClient
	clusterLinkIDFlag := &cli.StringFlag{
		Name:     clusterLinkIDFlagName,
		Aliases:  []string{"id"},
		Usage:    "Cluster Link ID",
		Required: true,
	}
	displayNameFlag := &cli.StringFlag{
		Name:     clusterLinkDisplayNameFlagName,
		Aliases:  []string{"dn"},
		Usage:    "Cluster Link display name",
		Required: true,
	}
	optionalDisplayNameFlag := &cli.StringFlag{
		Name:    clusterLinkDisplayNameFlagName,
		Aliases: []string{"dn"},
		Usage:   "New Cluster Link display name",
	}
	regionFlag := &cli.StringFlag{
		Name:     clusterLinkRegionFlagName,
		Usage:    "Cloud region for the Cluster Link proxy",
		Required: true,
	}
	optionalRegionFlag := &cli.StringFlag{
		Name:  clusterLinkRegionFlagName,
		Usage: "Filter Cluster Links by region",
	}
	acceptedClientCAFlag := &cli.StringFlag{
		Name:     clusterLinkAcceptedClientCAFileFlagName,
		Aliases:  []string{"ca"},
		Usage:    "PEM file containing the client CA accepted by Temporal Cloud",
		Required: true,
	}
	optionalAcceptedClientCAFlag := &cli.StringFlag{
		Name:    clusterLinkAcceptedClientCAFileFlagName,
		Aliases: []string{"ca"},
		Usage:   "Replacement PEM file containing the accepted client CA",
	}

	return CommandOut{Command: &cli.Command{
		Name:    "cluster-link",
		Aliases: []string{"cl"},
		Usage:   "Cluster Link operations",
		Before: func(ctx *cli.Context) error {
			var err error
			client, err = getClusterLinkClient(ctx)
			return err
		},
		Subcommands: []*cli.Command{
			{
				Name:    "create",
				Aliases: []string{"c"},
				Usage:   "Create a disconnected Cluster Link",
				Flags: []cli.Flag{
					displayNameFlag,
					regionFlag,
					acceptedClientCAFlag,
					RequestIDFlag,
				},
				Action: func(ctx *cli.Context) error {
					acceptedClientCA, err := os.ReadFile(ctx.String(clusterLinkAcceptedClientCAFileFlagName))
					if err != nil {
						return fmt.Errorf("read accepted client CA: %w", err)
					}
					response, err := client.create(
						ctx.String(clusterLinkDisplayNameFlagName),
						ctx.String(clusterLinkRegionFlagName),
						acceptedClientCA,
						ctx.String(RequestIDFlagName),
					)
					if err != nil {
						return err
					}
					return PrintProto(response)
				},
			},
			{
				Name:    "get",
				Aliases: []string{"g"},
				Usage:   "Get a Cluster Link",
				Flags:   []cli.Flag{clusterLinkIDFlag},
				Action: func(ctx *cli.Context) error {
					link, err := client.get(ctx.String(clusterLinkIDFlagName))
					if err != nil {
						return err
					}
					return PrintProto(link)
				},
			},
			{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "List Cluster Links",
				Flags: []cli.Flag{
					optionalRegionFlag,
					&cli.StringSliceFlag{
						Name:    clusterLinkConnectionStateFlagName,
						Aliases: []string{"cs"},
						Usage:   "Filter by observed connection state",
					},
					&cli.IntFlag{
						Name:  clusterLinkPageSizeFlagName,
						Usage: "Number of Cluster Links to request",
					},
					&cli.StringFlag{
						Name:  clusterLinkPageTokenFlagName,
						Usage: "Page token returned by a previous list request",
					},
				},
				Action: func(ctx *cli.Context) error {
					states, err := parseClusterLinkConnectionStates(
						ctx.StringSlice(clusterLinkConnectionStateFlagName),
					)
					if err != nil {
						return err
					}
					response, err := client.list(
						ctx.String(clusterLinkRegionFlagName),
						states,
						ctx.Int(clusterLinkPageSizeFlagName),
						ctx.String(clusterLinkPageTokenFlagName),
					)
					if err != nil {
						return err
					}
					return PrintProto(response)
				},
			},
			{
				Name:    "update",
				Aliases: []string{"u"},
				Usage:   "Update mutable Cluster Link specification fields",
				Flags: []cli.Flag{
					clusterLinkIDFlag,
					optionalDisplayNameFlag,
					optionalAcceptedClientCAFlag,
					ResourceVersionFlag,
					RequestIDFlag,
				},
				Action: func(ctx *cli.Context) error {
					if !ctx.IsSet(clusterLinkDisplayNameFlagName) &&
						!ctx.IsSet(clusterLinkAcceptedClientCAFileFlagName) {
						return fmt.Errorf("--%s or --%s is required",
							clusterLinkDisplayNameFlagName,
							clusterLinkAcceptedClientCAFileFlagName,
						)
					}
					response, err := client.update(
						ctx.String(clusterLinkIDFlagName),
						ctx.String(ResourceVersionFlagName),
						ctx.String(RequestIDFlagName),
						func(spec *clusterlink.ClusterLinkSpec) error {
							if ctx.IsSet(clusterLinkDisplayNameFlagName) {
								spec.DisplayName = ctx.String(clusterLinkDisplayNameFlagName)
							}
							if ctx.IsSet(clusterLinkAcceptedClientCAFileFlagName) {
								acceptedClientCA, err := os.ReadFile(
									ctx.String(clusterLinkAcceptedClientCAFileFlagName),
								)
								if err != nil {
									return fmt.Errorf("read accepted client CA: %w", err)
								}
								if spec.Endpoint == nil {
									return errors.New("cluster link specification has no endpoint")
								}
								if spec.Endpoint.Security == nil {
									spec.Endpoint.Security = &clusterlink.ClusterLinkEndpointSecuritySpec{}
								}
								spec.Endpoint.Security.AcceptedClientCa = acceptedClientCA
							}
							return nil
						},
					)
					if err != nil {
						return err
					}
					return PrintProto(response)
				},
			},
			clusterLinkDesiredStateCommand(
				"connect",
				"Request connection to the assigned S2S proxy",
				clusterlink.DESIRED_CONNECTION_STATE_CONNECTED,
				clusterLinkIDFlag,
				func() *ClusterLinkClient { return client },
			),
			clusterLinkDesiredStateCommand(
				"disconnect",
				"Request disconnection from the assigned S2S proxy",
				clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
				clusterLinkIDFlag,
				func() *ClusterLinkClient { return client },
			),
			{
				Name:    "delete",
				Aliases: []string{"d"},
				Usage:   "Delete a detached Cluster Link with no consumers",
				Flags: []cli.Flag{
					clusterLinkIDFlag,
					ResourceVersionFlag,
					RequestIDFlag,
				},
				Action: func(ctx *cli.Context) error {
					confirmed, err := ConfirmPrompt(ctx, "delete the Cluster Link?")
					if err != nil {
						return err
					}
					if !confirmed {
						return nil
					}
					response, err := client.delete(
						ctx.String(clusterLinkIDFlagName),
						ctx.String(ResourceVersionFlagName),
						ctx.String(RequestIDFlagName),
					)
					if err != nil {
						return err
					}
					return PrintProto(response)
				},
			},
		},
	}}, nil
}

func clusterLinkDesiredStateCommand(
	name string,
	usage string,
	desired clusterlink.ClusterLinkSpec_DesiredConnectionState,
	clusterLinkIDFlag cli.Flag,
	getClient func() *ClusterLinkClient,
) *cli.Command {
	return &cli.Command{
		Name:  name,
		Usage: usage,
		Flags: []cli.Flag{
			clusterLinkIDFlag,
			ResourceVersionFlag,
			RequestIDFlag,
		},
		Action: func(ctx *cli.Context) error {
			response, err := getClient().update(
				ctx.String(clusterLinkIDFlagName),
				ctx.String(ResourceVersionFlagName),
				ctx.String(RequestIDFlagName),
				func(spec *clusterlink.ClusterLinkSpec) error {
					spec.DesiredConnectionState = desired
					return nil
				},
			)
			if err != nil {
				return err
			}
			return PrintProto(response)
		},
	}
}
