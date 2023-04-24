package app

import (
	"context"
	"fmt"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
)

type APIKeyClient struct {
	authClient authservice.AuthServiceClient
	ctx        context.Context
}

func NewAPIKeyClient(ctx context.Context, conn *grpc.ClientConn) *APIKeyClient {
	return &APIKeyClient{
		authClient: authservice.NewAuthServiceClient(conn),
		ctx:        ctx,
	}
}

type GetAPIKeyClientFn func(ctx *cli.Context) (*APIKeyClient, error)

func GetAPIKeyClient(ctx *cli.Context) (*APIKeyClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return NewAPIKeyClient(ct, conn), nil
}

func (s *APIKeyClient) createAPIKey(
	displayName string,
	description string,
	expiry time.Time,
	requestID string,
) error {
	expiryts, err := types.TimestampProto(expiry)
	if err != nil {
		return fmt.Errorf("failed to convert timestamp to proto: %s", err)
	}
	resp, err := s.authClient.CreateAPIKey(s.ctx, &authservice.CreateAPIKeyRequest{
		Spec: &auth.APIKeySpec{
			DisplayName: displayName,
			Description: description,
			ExpiryTime:  expiryts,
		},
		RequestId: requestID,
	})
	if err != nil {
		return err
	}
	return PrintProto(resp)
}

func (s *APIKeyClient) listAPIKey() error {

	totalRes := &authservice.GetAPIKeysResponse{}
	pageToken := ""
	for {
		resp, err := s.authClient.GetAPIKeys(s.ctx, &authservice.GetAPIKeysRequest{
			PageToken: pageToken,
		})
		if err != nil {
			return err
		}
		totalRes.ApiKeys = append(totalRes.ApiKeys, resp.ApiKeys...)
		// Check if we should continue paging
		pageToken = resp.NextPageToken
		if len(pageToken) == 0 {
			return PrintProto(totalRes)
		}
	}
}

func (s *APIKeyClient) getAPIKey(
	id string,
) (*auth.APIKey, error) {
	resp, err := s.authClient.GetAPIKey(s.ctx, &authservice.GetAPIKeyRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return resp.ApiKey, nil
}

func (s *APIKeyClient) deleteAPIKey(
	id string,
	resourceVersion string,
	requestID string,
) error {
	resp, err := s.authClient.DeleteAPIKey(s.ctx, &authservice.DeleteAPIKeyRequest{
		Id:              id,
		ResourceVersion: resourceVersion,
		RequestId:       requestID,
	})
	if err != nil {
		return err
	}
	return PrintProto(resp)
}

func NewAPIKeyCommand(getAPIKeyClientFn GetAPIKeyClientFn) (CommandOut, error) {
	var c *APIKeyClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "apikey",
			Aliases: []string{"ak"},
			Usage:   "APIKey operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getAPIKeyClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:    "create",
					Usage:   "Create an user apikey",
					Aliases: []string{"c"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "name",
							Usage:    "the display name of the apikey",
							Required: true,
							Aliases:  []string{"n"},
						},
						&cli.StringFlag{
							Name:    "description",
							Usage:   "the description of the apikey",
							Aliases: []string{"desc"},
						},
						&cli.DurationFlag{
							Name:    "duration",
							Usage:   "the duration from now when the apikey will expire, will be ignored if expiry flag is set",
							Aliases: []string{"d"},
						},
						&cli.TimestampFlag{
							Name:    "expiry",
							Usage:   fmt.Sprintf("the absolute timestamp when the apikey will expire, example: '%s'", time.Now().Format(time.RFC1123)),
							Aliases: []string{"e"},
							Layout:  "Mon, 17 Apr 2023 13:22:15 PDT",
						},
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						expiry := ctx.Timestamp("expiry")
						if expiry == nil || expiry.IsZero() {
							expiryPeriod := ctx.Duration("duration")
							if expiryPeriod == 0 {
								return fmt.Errorf("no expiry was set")
							}
							e := time.Now().Add(expiryPeriod)
							expiry = &e
						}
						return c.createAPIKey(
							ctx.String("name"),
							ctx.String("description"),
							*expiry,
							ctx.String(RequestIDFlagName),
						)
					},
				},
				{
					Name:    "get",
					Usage:   "Get an user apikey",
					Aliases: []string{"g"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "id",
							Usage:    "The id of the apikey to get",
							Required: true,
							Aliases:  []string{"i"},
						},
					},
					Action: func(ctx *cli.Context) error {
						apikey, err := c.getAPIKey(ctx.String("id"))
						if err != nil {
							return err
						}
						return PrintProto(apikey)
					},
				},
				{
					Name:    "list",
					Usage:   "List user apikeys",
					Aliases: []string{"l"},
					Flags:   []cli.Flag{},
					Action: func(ctx *cli.Context) error {
						return c.listAPIKey()
					},
				},
				{
					Name:    "delete",
					Usage:   "Delete an user apikey",
					Aliases: []string{"d"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "id",
							Usage:    "The id of the apikey to delete",
							Required: true,
							Aliases:  []string{"i"},
						},
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						rv := ctx.String(ResourceVersionFlagName)
						if rv == "" {
							apikey, err := c.getAPIKey(ctx.String("id"))
							if err != nil {
								return err
							}
							rv = apikey.ResourceVersion
						}
						return c.deleteAPIKey(
							ctx.String("id"),
							rv,
							ctx.String(RequestIDFlagName),
						)
					},
				},
			},
		},
	}, nil
}
