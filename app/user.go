package app

import (
	"context"
	"fmt"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
)

const (
	userIDFlagName    = "user-id"
	userEmailFlagName = "user-email"
	rolesFlagName     = "roles"
)

var (
	userIDFlag = &cli.StringFlag{
		Name:    userIDFlagName,
		Usage:   "The user id",
		Aliases: []string{"i"},
	}
	userEmailFlag = &cli.StringFlag{
		Name:    userEmailFlagName,
		Usage:   "The user email address of the user to be invited",
		Aliases: []string{"e"},
	}
	multipleUserEmailFlag = &cli.StringSliceFlag{
		Name:     userEmailFlagName,
		Usage:    "The user email address of the user to be invited, you can supply this flag multiple times to invite multiple users in a single request",
		Required: true,
		Aliases:  []string{"e"},
	}
	multipleRoleFlag = &cli.StringSliceFlag{
		Name:     rolesFlagName,
		Usage:    "The role that should be added to each invited use, you can supply this flag multiple times to add multiple roles to each user in a single request",
		Required: true,
		Aliases:  []string{"ro"},
	}
)

type UserClient struct {
	client authservice.AuthServiceClient
	ctx    context.Context
}

type GetUserClientFn func(ctx *cli.Context) (*UserClient, error)

func GetUserClient(ctx *cli.Context) (*UserClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &UserClient{
		client: authservice.NewAuthServiceClient(conn),
		ctx:    ct,
	}, nil
}

func (c *UserClient) listUsers() error {
	totalRes := &authservice.GetUsersResponse{}
	pageToken := ""
	for {
		res, err := c.client.GetUsers(c.ctx, &authservice.GetUsersRequest{
			PageToken: pageToken,
		})
		if err != nil {
			return err
		}
		totalRes.Users = append(totalRes.Users, res.Users...)
		// Check if we should continue paging
		pageToken = res.NextPageToken
		if len(pageToken) == 0 {
			return PrintProto(totalRes)
		}
	}
}

func (c *UserClient) getUser(userID, userEmail string) (*auth.User, error) {
	res, err := c.client.GetUser(c.ctx, &authservice.GetUserRequest{
		UserId:    userID,
		UserEmail: userEmail,
	})
	if err != nil {
		return nil, err
	}
	if res.User == nil || res.User.Id == "" {
		// this should never happen, the server should return an error when the user is not found
		return nil, fmt.Errorf("invalid user returned by server")
	}
	return res.User, nil
}

func (c *UserClient) inviteUsers(
	ctx *cli.Context,
	emails []string,
	roleIDs []string,
) error {
	req := &authservice.InviteUsersRequest{
		Specs:     make([]*auth.UserSpec, len(emails)),
		RequestId: ctx.String(RequestIDFlagName),
	}
	for i := range emails {
		req.Specs[i] = &auth.UserSpec{
			Email: emails[i],
			Roles: roleIDs,
		}
	}
	resp, err := c.client.InviteUsers(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to invite users: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func (c *UserClient) resendInvitation(
	ctx *cli.Context,
	userID string,
) error {
	req := &authservice.ResendUserInviteRequest{
		UserId:    userID,
		RequestId: ctx.String(RequestIDFlagName),
	}
	resp, err := c.client.ResendUserInvite(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to resend invitation for user: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func (c *UserClient) deleteUser(
	ctx *cli.Context,
	userID string,
	email string,
) error {

	res, err := c.client.GetUser(c.ctx, &authservice.GetUserRequest{
		UserEmail: email,
		UserId:    userID,
	})
	if err != nil {
		return err
	}
	req := &authservice.DeleteUserRequest{
		UserId:          res.User.Id,
		ResourceVersion: ctx.String(ResourceVersionFlagName),
		RequestId:       ctx.String(RequestIDFlagName),
	}
	if req.ResourceVersion == "" {
		req.ResourceVersion = res.User.ResourceVersion
	}
	resp, err := c.client.DeleteUser(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to update user: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func (c *UserClient) updateUser(
	ctx *cli.Context,
	email string,
	roleNames []string,
) error {

	res, err := c.client.GetUser(c.ctx, &authservice.GetUserRequest{
		UserEmail: email,
	})
	if err != nil {
		return err
	}
	req := &authservice.UpdateUserRequest{
		UserId: res.User.Id,
		Spec: &auth.UserSpec{
			Email: email,
			Roles: roleNames,
		},
		ResourceVersion: ctx.String(ResourceVersionFlagName),
		RequestId:       ctx.String(RequestIDFlagName),
	}
	if req.ResourceVersion == "" {
		req.ResourceVersion = res.User.ResourceVersion
	}
	resp, err := c.client.UpdateUser(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to update user: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func (c *UserClient) assignNamespacePermission(
	ctx *cli.Context,
	email string,
	namespace string,
	permission string,
) error {

	res, err := c.client.GetUser(c.ctx, &authservice.GetUserRequest{
		UserEmail: email,
	})
	if err != nil {
		return err
	}
	req := &authservice.UpdateUserNamespacePermissionsRequest{
		Namespace: namespace,
		UserNamespacePermissions: []*auth.UserNamespacePermissions{
			&auth.UserNamespacePermissions{
				UserId:      res.User.Id,
				ActionGroup: auth.NamespaceActionGroup(auth.NamespaceActionGroup_value[permission]),
			},
		},
		RequestId: ctx.String(RequestIDFlagName),
	}
	resp, err := c.client.UpdateUserNamespacePermissions(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to update user's namespace permissions: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func NewUserCommand(getUserClientFn GetUserClientFn) (CommandOut, error) {
	var c *UserClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "user",
			Aliases: []string{"u"},
			Usage:   "User operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getUserClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:    "list",
					Usage:   "List users",
					Aliases: []string{"l"},
					Flags:   []cli.Flag{},
					Action: func(ctx *cli.Context) error {
						return c.listUsers()
					},
				},
				{
					Name:    "get",
					Usage:   "Get user information",
					Aliases: []string{"g"},
					Flags: []cli.Flag{
						userIDFlag,
						userEmailFlag,
					},
					Action: func(ctx *cli.Context) error {
						n, err := c.getUser(ctx.String(userIDFlagName), ctx.String(userEmailFlagName))
						if err != nil {
							return err
						}
						return PrintProto(n)
					},
				},
				{
					Name:    "invite",
					Usage:   "Invites users to Temporal Cloud",
					Aliases: []string{"i"},
					Flags: []cli.Flag{
						multipleUserEmailFlag,
						multipleRoleFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.inviteUsers(
							ctx,
							ctx.StringSlice(userEmailFlagName),
							ctx.StringSlice(rolesFlagName),
						)
					},
				},
				{
					Name:    "delete",
					Usage:   "Delete user from Temporal Cloud",
					Aliases: []string{"d"},
					Flags: []cli.Flag{
						userIDFlag,
						userEmailFlag,
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.deleteUser(
							ctx,
							ctx.String(userIDFlagName),
							ctx.String(userEmailFlagName),
						)
					},
				},
				{
					Name:    "resend-invitation",
					Usage:   "Resend invitation to a user on Temporal Cloud",
					Aliases: []string{"ri"},
					Flags: []cli.Flag{
						userIDFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.resendInvitation(
							ctx,
							ctx.String(userIDFlagName),
						)
					},
				},
				{
					Name:    "roles",
					Usage:   "Update roles assigned to users",
					Aliases: []string{"r"},
					Subcommands: []*cli.Command{
						{
							Name:    "set",
							Usage:   "set the roles assigned to the user",
							Aliases: []string{"s"},
							Flags: []cli.Flag{
								userEmailFlag,
								multipleRoleFlag,
								RequestIDFlag,
								ResourceVersionFlag,
							},
							Action: func(ctx *cli.Context) error {
								return c.updateUser(
									ctx,
									ctx.String(userEmailFlagName),
									ctx.StringSlice(rolesFlagName),
								)
							},
						},
						{
							Name:    "set-namespace-permission",
							Usage:   "set namespace permissions for a user",
							Aliases: []string{"sn"},
							Flags: []cli.Flag{
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringFlag{
									Name:  "namespace",
									Usage: "the namespace to assign permission to",
								},
								&cli.StringFlag{
									Name:  "permission",
									Usage: "the permission to assign",
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.assignNamespacePermission(
									ctx,
									ctx.String(userEmailFlagName),
									ctx.String("namespace"),
									ctx.String("permission"),
								)
							},
						},
					},
				},
			},
		},
	}, nil
}
