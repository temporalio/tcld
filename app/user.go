package app

import (
	"context"
	"fmt"
	"strings"

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

func (c *UserClient) listUsers(
	ctx *cli.Context,
	namespace string,
) error {
	totalRes := &authservice.GetUsersResponse{}
	pageToken := ""
	for {
		res, err := c.client.GetUsers(c.ctx, &authservice.GetUsersRequest{
			PageToken: pageToken,
			Namespace: namespace,
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
	if userID != "" && userEmail != "" {
		return nil, fmt.Errorf("both user-id and user-email set")
	}
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
	userEmail string,
) error {
	user, err := c.getUser(userID, userEmail)
	if err != nil {
		return err
	}
	req := &authservice.ResendUserInviteRequest{
		UserId:    user.Id,
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
	userEmail string,
) error {
	if userID != "" && userEmail != "" {
		return fmt.Errorf("both user-id and user-email set")
	}
	res, err := c.client.GetUser(c.ctx, &authservice.GetUserRequest{
		UserEmail: userEmail,
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
	userID string,
	userEmail string,
	roleNames []string,
) error {
	user, err := c.getUser(userID, userEmail)
	if err != nil {
		return err
	}
	req := &authservice.UpdateUserRequest{
		UserId: user.Id,
		Spec: &auth.UserSpec{
			Email: user.Spec.Email,
			Roles: roleNames,
		},
		ResourceVersion: ctx.String(ResourceVersionFlagName),
		RequestId:       ctx.String(RequestIDFlagName),
	}
	if req.ResourceVersion == "" {
		req.ResourceVersion = user.ResourceVersion
	}
	resp, err := c.client.UpdateUser(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to update user: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func (c *UserClient) assignNamespacePermission(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespace string,
	permission string,
) error {
	user, err := c.getUser(userID, userEmail)
	if err != nil {
		return err
	}
	p := strings.ToLower(strings.TrimSpace(permission))
	var ag auth.NamespaceActionGroup
	for n, v := range auth.NamespaceActionGroup_value {
		if strings.ToLower(n) == p {
			ag = auth.NamespaceActionGroup(v)
			break
		}
	}
	if ag == auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED {
		return fmt.Errorf("invalid permission")
	}
	req := &authservice.UpdateUserNamespacePermissionsRequest{
		Namespace: namespace,
		UserNamespacePermissions: []*auth.UserNamespacePermissions{
			{
				UserId:      user.Id,
				ActionGroup: ag,
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
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "namespace",
							Usage:    "List users that have access to the namespace",
							Required: true,
							Aliases:  []string{"n"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listUsers(ctx, ctx.String("namespace"))
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
						userEmailFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.resendInvitation(
							ctx,
							ctx.String(userIDFlagName),
							ctx.String(userEmailFlagName),
						)
					},
				},
				{
					Name:    "update",
					Usage:   "Update users",
					Aliases: []string{"r"},
					Subcommands: []*cli.Command{
						{
							Name:    "set-roles",
							Usage:   "set the roles assigned to the user",
							Aliases: []string{"s"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								multipleRoleFlag,
								RequestIDFlag,
								ResourceVersionFlag,
							},
							Action: func(ctx *cli.Context) error {
								return c.updateUser(
									ctx,
									ctx.String(userIDFlagName),
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
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringFlag{
									Name:     "namespace",
									Usage:    "the namespace to assign permission to",
									Required: true,
									Aliases:  []string{"n"},
								},
								&cli.StringFlag{
									Name:     "permission",
									Usage:    "the permission to assign",
									Required: true,
									Aliases:  []string{"p"},
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.assignNamespacePermission(
									ctx,
									ctx.String(userIDFlagName),
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
