package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
)

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

func (s *APIKeyClient) listAPIKey() error {

	totalRes := &authservice.GetAPIKeysResponse{}
	pageToken := ""
	for {
		resp, err := s.client.GetAPIKeys(s.ctx, &authservice.GetAPIKeysRequest{
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

// a hacky version of time.ParseDuration() which considers days ('d') a valid time unit.
func parseDuration(s string) (time.Duration, error) {
	var d time.Duration
	durationString := s
	parts := strings.Split(s, "d")
	if len(parts) == 2 {
		days, err := strconv.ParseInt(parts[0], 10, 32)
		if err != nil {
			return d, fmt.Errorf("time: invalid duration \"%s\"", s)
		}
		if days < 0 {
			return d, errors.New("expiration cannot be negative")
		}
		// note: this calculation is _technically_ incorrect,
		// due to daylight savings time zone transitions.
		// however, when the TTL is specified in days,
		// we can afford to be off by +/- an hour.
		d += 24 * time.Duration(days) * time.Hour
		durationString = parts[1]
	}
	if len(durationString) == 0 {
		return d, nil
	}
	pd, err := time.ParseDuration(durationString)
	if err != nil {
		return d, err
	}
	if pd < 0 {
		return d, errors.New("expiration cannot be negative")
	}
	d += pd
	return d, nil
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
							Usage:   "the duration from now when the apikey will expire, will be ignored if expiry flag is set, example: '30d' or '2d12h",
							Aliases: []string{"d"},
						},
						&cli.TimestampFlag{
							Name:    "expiry",
							Usage:   fmt.Sprintf("the absolute timestamp (RFC3339) when the apikey will expire, example: '%s'", time.Now().Format(time.RFC3339)),
							Aliases: []string{"e"},
							Layout:  time.RFC3339,
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
							d, err := parseDuration(expiryPeriod)
							if err != nil {
								return fmt.Errorf("failed to parse duration: %w", err)
							}
							if d == 0 {
								return fmt.Errorf("no expiry was set")
							}
							e := time.Now().UTC().Add(d)
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
					Usage:   "List apikeys",
					Aliases: []string{"l"},
					Flags:   []cli.Flag{},
					Action: func(ctx *cli.Context) error {
						return c.listAPIKey()
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
