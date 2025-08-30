package app

import (
	"context"
	"fmt"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/utils"
	"github.com/urfave/cli/v2"
)

const (
	ownerIDFlagName   = "owner-id"
	ownerTypeFlagName = "owner-type"
)

const (
	OwnerTypeUser           = "user"
	OwnerTypeServiceAccount = "service-account"
)

var OwnerTypes = []string{
	OwnerTypeUser,
	OwnerTypeServiceAccount,
}

type (
	APIKeyClient struct {
		client authservice.AuthServiceClient
		ctx    context.Context
	}
	GetAPIKeyClientFn func(ctx *cli.Context) (*APIKeyClient, error)
)

func GetAPIKeyClient(ctx *cli.Context) (*APIKeyClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &APIKeyClient{
		client: authservice.NewAuthServiceClient(conn),
		ctx:    ct,
	}, nil
}

func validateOwnerType(t string) error {
	if len(t) == 0 {
		return nil
	}
	for _, ownerType := range OwnerTypes {
		if t == ownerType {
			return nil
		}
	}
	return fmt.Errorf("invalid owner type: '%s'", t)
}

func (s *APIKeyClient) createAPIKey(
	displayName string,
	description string,
	expiry time.Time,
	requestID string,
) error {
	expiryts, err := types.TimestampProto(expiry)
	if err != nil {
		return fmt.Errorf("failed to convert timestamp to proto: %w", err)
	}
	resp, err := s.client.CreateAPIKey(s.ctx, &authservice.CreateAPIKeyRequest{
		Spec: &auth.APIKeySpec{
			AccessType:  auth.APIKEY_ACCESS_TYPE_INHERIT_OWNER_ACCESS,
			Disabled:    false,
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

func (s *APIKeyClient) createServiceAccountAPIKey(
	serviceAccountID string,
	displayName string,
	description string,
	expiry time.Time,
	requestID string,
) error {
	expiryts, err := types.TimestampProto(expiry)
	if err != nil {
		return fmt.Errorf("failed to convert timestamp to proto: %w", err)
	}
	resp, err := s.client.CreateServiceAccountAPIKey(s.ctx, &authservice.CreateServiceAccountAPIKeyRequest{
		ServiceAccountId: serviceAccountID,
		Spec: &auth.APIKeySpec{
			AccessType:  auth.APIKEY_ACCESS_TYPE_INHERIT_OWNER_ACCESS,
			Disabled:    false,
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

func (s *APIKeyClient) listAPIKey(ownerID, ownerType string) error {
	totalRes := &authservice.GetAPIKeysResponse{}
	pageToken := ""
	for {
		resp, err := s.client.GetAPIKeys(s.ctx, &authservice.GetAPIKeysRequest{
			PageToken: pageToken,
			OwnerId:   ownerID,
			OwnerType: ownerType,
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
	resp, err := s.client.GetAPIKey(s.ctx, &authservice.GetAPIKeyRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return resp.ApiKey, nil
}

func (s *APIKeyClient) updateAPIKey(
	id string,
	spec *auth.APIKeySpec,
	resourceVersion string,
	requestID string,
) error {
	resp, err := s.client.UpdateAPIKey(s.ctx, &authservice.UpdateAPIKeyRequest{
		Id:              id,
		Spec:            spec,
		ResourceVersion: resourceVersion,
		RequestId:       requestID,
	})
	if err != nil {
		return err
	}
	return PrintProto(resp)
}

func (s *APIKeyClient) deleteAPIKey(
	id string,
	resourceVersion string,
	requestID string,
) error {
	resp, err := s.client.DeleteAPIKey(s.ctx, &authservice.DeleteAPIKeyRequest{
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
				// TODO: need a create for service account command
				{
					Name:    "create",
					Usage:   "Create an apikey. Make sure to copy the secret or else you will not be able to retrieve it again.",
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
						&cli.StringFlag{
							Name:    "duration",
							Usage:   "the duration from now when the apikey will expire, will be ignored if expiry flag is set, examples: '1.5y', '30d', '4d12h'",
							Aliases: []string{"d"},
						},
						&cli.TimestampFlag{
							Name:    "expiry",
							Usage:   fmt.Sprintf("the absolute timestamp (RFC3339) when the apikey will expire, example: '%s'", time.Now().Format(time.RFC3339)),
							Aliases: []string{"e"},
							Layout:  time.RFC3339,
						},
						&cli.StringFlag{
							Name:    "service-account-id",
							Usage:   "setting this flag will create an api key for a service account, not a user",
							Aliases: []string{"si"},
						},
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						expiry := ctx.Timestamp("expiry")
						if expiry == nil || expiry.IsZero() {
							expiryPeriod := ctx.String("duration")
							if expiryPeriod == "" {
								return fmt.Errorf("no expiry was set")
							}
							d, err := utils.ParseDuration(expiryPeriod)
							if err != nil {
								return fmt.Errorf("failed to parse duration: %w", err)
							}
							if d <= 0 {
								return fmt.Errorf("expiration must be positive: %s", expiryPeriod)
							}
							e := time.Now().UTC().Add(d)
							expiry = &e
						}
						// create api key for service account
						if ctx.String("service-account-id") != "" {
							return c.createServiceAccountAPIKey(
								ctx.String("service-account-id"),
								ctx.String("name"),
								ctx.String("description"),
								*expiry,
								ctx.String(RequestIDFlagName),
							)
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
					Usage:   "Get an apikey",
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
					Usage:   "List API keys",
					Aliases: []string{"l"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    ownerIDFlagName,
							Usage:   "Filter API keys by owner ID",
							Aliases: []string{"oid"},
						},
						&cli.StringFlag{
							Name:    ownerTypeFlagName,
							Usage:   fmt.Sprintf("Filter API keys by owner type (i.e. %s)", formatStringSlice(OwnerTypes)),
							Aliases: []string{"ot"},
						},
					},
					Action: func(ctx *cli.Context) error {
						ownerType := ctx.String(ownerTypeFlagName)
						if err := validateOwnerType(ownerType); err != nil {
							return err
						}
						return c.listAPIKey(
							ctx.String(ownerIDFlagName),
							ownerType,
						)
					},
				},
				{
					Name:    "delete",
					Usage:   "Delete an apikey",
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
				{
					Name:    "disable",
					Usage:   "Disable an apikey",
					Aliases: []string{"da"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "id",
							Usage:    "The id of the apikey to disable",
							Required: true,
							Aliases:  []string{"i"},
						},
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						apikey, err := c.getAPIKey(ctx.String("id"))
						if err != nil {
							return err
						}
						spec := apikey.Spec
						if spec.Disabled {
							return fmt.Errorf("apikey is already disabled")
						}
						spec.Disabled = true
						rv := ctx.String(ResourceVersionFlagName)
						if rv == "" {
							rv = apikey.ResourceVersion
						}
						return c.updateAPIKey(
							ctx.String("id"),
							spec,
							rv,
							ctx.String(RequestIDFlagName),
						)
					},
				},
				{
					Name:    "enable",
					Usage:   "Enable a disabled apikey",
					Aliases: []string{"ea"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "id",
							Usage:    "The id of the apikey to enable",
							Required: true,
							Aliases:  []string{"i"},
						},
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						apikey, err := c.getAPIKey(ctx.String("id"))
						if err != nil {
							return err
						}
						spec := apikey.Spec
						if !spec.Disabled {
							return fmt.Errorf("apikey is already enabled")
						}
						spec.Disabled = false
						rv := ctx.String(ResourceVersionFlagName)
						if rv == "" {
							rv = apikey.ResourceVersion
						}
						return c.updateAPIKey(
							ctx.String("id"),
							spec,
							rv,
							ctx.String(RequestIDFlagName),
						)
					},
				},
			},
		},
	}, nil
}
