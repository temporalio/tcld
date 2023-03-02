package app

import (
	"context"
	"fmt"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
)

const (
	userIDFlagName          = "user-id"
	userEmailFlagName       = "user-email"
	rolesFlagName           = "roles"
	namespaceAccessFlagName = "namespace-access"
	accountAccessFlagName   = "account-access"
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
	multipleRoleFlag = &cli.StringSliceFlag{
		Name:     rolesFlagName,
		Usage:    "The role that should be added to each invited use, you can supply this flag multiple times to add multiple roles to each user in a single request",
		Required: true,
		Aliases:  []string{"ro"},
	}
	namespaceAccessFlag = &cli.StringFlag{
		Name:    namespaceAccessFlagName,
		Usage:   fmt.Sprintf("The namespace access, should be one of: %s", namespaceActionGroups),
		Aliases: []string{"na"},
	}
	namespaceFlag = &cli.StringFlag{
		Name:    NamespaceFlagName,
		Usage:   "The namespace to give access to",
		Aliases: []string{"n"},
	}
	accountAccessFlag = &cli.StringFlag{
		Name:    accountAccessFlagName,
		Usage:   fmt.Sprintf("The account access, should be one of: %s", accountActionGroups),
		Aliases: []string{"aa"},
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
	if userID == "" && userEmail == "" {
		return nil, fmt.Errorf("both user-id and user-email not set")
	}

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

func (c *UserClient) getUserAndRoles(userID, userEmail string) (*auth.User, []*auth.Role, error) {
	user, err := c.getUser(userID, userEmail)
	if err != nil {
		return nil, nil, err
	}
	var pageToken string
	var roles []*auth.Role
	for {
		res, err := c.client.GetRoles(c.ctx, &authservice.GetRolesRequest{
			PageToken: pageToken,
			UserId:    user.Id,
		})
		if err != nil {
			return nil, nil, err
		}
		roles = append(roles, res.Roles...)
		// Check if we should continue paging
		pageToken = res.NextPageToken
		if len(pageToken) == 0 {
			break
		}
	}

	return user, roles, nil
}

func (c *UserClient) inviteUsers(
	ctx *cli.Context,
	emails []string,
	roleIDs []string,
	access string,
) error {
	if len(roleIDs) == 0 && access == "" {
		return fmt.Errorf("atleast one of role-ids or access needs to be set")
	}
	if len(roleIDs) > 0 && access != "" {
		return fmt.Errorf("cannot set both role-ids and access")
	}
	if access != "" {
		res, err := getAccountRoles(c.ctx, c.client, access)
		if err != nil {
			return err
		}
		if len(res.Roles) != 1 {
			return fmt.Errorf("failed to get the account role for given access, roles found: %s", res.Roles)
		}
		roleIDs = append(roleIDs, res.Roles[0].Id)
	}
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
	if userID == "" && userEmail == "" {
		return fmt.Errorf("both user-id and user-email cannot be empty")
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

func (c *UserClient) performUpdate(ctx *cli.Context, user *auth.User) error {
	req := &authservice.UpdateUserRequest{
		UserId:          user.Id,
		Spec:            user.Spec,
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
	user.Spec.Roles = roleNames
	return c.performUpdate(ctx, user)
}

func (c *UserClient) setAccountAccess(
	ctx *cli.Context,
	userID string,
	userEmail string,
	accountAccess string,
) error {
	user, userRoles, err := c.getUserAndRoles(userID, userEmail)
	if err != nil {
		return err
	}
	role, err := getAccountRole(c.ctx, c.client, accountAccess)
	if err != nil {
		return err
	}
	for i := range userRoles {
		if userRoles[i].Id == role.Id {
			return fmt.Errorf("user already assigned '%s' account role", role.Id)
		}
	}
	for i := range userRoles {
		if userRoles[i].Spec.AccountRole != nil && userRoles[i].Spec.AccountRole.ActionGroup != auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
			if role.Spec.AccountRole.ActionGroup == auth.ACCOUNT_ACTION_GROUP_ADMIN {
				// assignign the user account admin role
				y, err := ConfirmPrompt(ctx, "Assigning admin role to user, please confirm")
				if err != nil || !y {
					return err
				}
				userRoles = []*auth.Role{role}
			} else {
				userRoles[i] = role
			}
		}
	}
	roleNames := make([]string, len(userRoles))
	for i := range userRoles {
		roleNames[i] = userRoles[i].Id
	}
	user.Spec.Roles = roleNames
	return c.performUpdate(ctx, user)
}

func (c *UserClient) updateUserNamespacePermissions(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespace string,
	actionGroup auth.NamespaceActionGroup,
) error {
	user, err := c.getUser(userID, userEmail)
	if err != nil {
		return err
	}
	req := &authservice.UpdateUserNamespacePermissionsRequest{
		Namespace: namespace,
		UserNamespacePermissions: []*auth.UserNamespacePermissions{
			{
				UserId:      user.Id,
				ActionGroup: actionGroup,
			},
		},
		RequestId: ctx.String(RequestIDFlagName),
	}
	resp, err := c.client.UpdateUserNamespacePermissions(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to update user's namespace access: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func (c *UserClient) assignNamespacePermission(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespace string,
	access string,
) error {
	ag, err := toNamespaceActionGroup(access)
	if err != nil {
		return err
	}
	return c.updateUserNamespacePermissions(ctx, userID, userEmail, namespace, ag)
}

func (c *UserClient) clearNamespacePermission(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespace string,
) error {
	return c.updateUserNamespacePermissions(ctx, userID, userEmail, namespace, auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED)
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
							Name:    "namespace",
							Usage:   "List users that have access to the namespace",
							Aliases: []string{"n"},
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
					Usage:   "Invite users to Temporal Cloud",
					Aliases: []string{"i"},
					Flags: []cli.Flag{
						&cli.StringSliceFlag{
							Name:     userEmailFlagName,
							Usage:    "The email address of the user, you can supply this flag multiple times to invite multiple users in a single request",
							Required: true,
							Aliases:  []string{"e"},
						},
						&cli.StringSliceFlag{
							Name:    rolesFlagName,
							Usage:   "The roles to assign to each user. (cannot be used with access)",
							Aliases: []string{"ro"},
						},
						&cli.StringFlag{
							Name:    "access",
							Usage:   fmt.Sprintf("The account access to assign to the user. (cannot be used with user roles) one of: %s", getAccountActionGroups()),
							Aliases: []string{"a"},
						},
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.inviteUsers(
							ctx,
							ctx.StringSlice(userEmailFlagName),
							ctx.StringSlice(rolesFlagName),
							ctx.String("access"),
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
					Usage:   "Update users settings",
					Aliases: []string{"u"},
					Subcommands: []*cli.Command{
						{
							Name:    "set-roles",
							Usage:   "Set user roles",
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
							Name:    "add-role",
							Usage:   "Add role to a user",
							Aliases: []string{"a"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
							},
							Action: func(ctx *cli.Context) error {
								return nil
							},
						},
						{
							Name:    "remove-role",
							Usage:   "Remove a role from user",
							Aliases: []string{"r"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
							},
							Action: func(ctx *cli.Context) error {
								return nil
							},
						},
						{
							Name:    "set-account-access",
							Usage:   "Set user's account access",
							Aliases: []string{"sna"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringFlag{
									Name:     "access",
									Usage:    fmt.Sprintf("The access, should be one of: %s", accountActionGroups),
									Required: true,
									Aliases:  []string{"a"},
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.assignNamespacePermission(
									ctx,
									ctx.String(userIDFlagName),
									ctx.String(userEmailFlagName),
									ctx.String("namespace"),
									ctx.String("access"),
								)
							},
						},

						{
							Name:    "set-namespace-access",
							Usage:   "Set user's namespace access",
							Aliases: []string{"sna"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringFlag{
									Name:     "namespace",
									Usage:    "The namespace to assign access to",
									Required: true,
									Aliases:  []string{"n"},
								},
								&cli.StringFlag{
									Name:     "access",
									Usage:    fmt.Sprintf("The access, should be one of: %s", namespaceActionGroups),
									Required: true,
									Aliases:  []string{"a"},
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.assignNamespacePermission(
									ctx,
									ctx.String(userIDFlagName),
									ctx.String(userEmailFlagName),
									ctx.String("namespace"),
									ctx.String("access"),
								)
							},
						},
						{
							Name:    "remove-namespace-access",
							Usage:   "Remove user's namespace accesss",
							Aliases: []string{"rna"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringFlag{
									Name:     "namespace",
									Usage:    "the namespace to remove access",
									Required: true,
									Aliases:  []string{"n"},
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.clearNamespacePermission(
									ctx,
									ctx.String(userIDFlagName),
									ctx.String(userEmailFlagName),
									ctx.String("namespace"),
								)
							},
						},
					},
				},
			},
		},
	}, nil
}
