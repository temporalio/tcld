package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
	"strings"
)

const (
	userIDFlagName              = "user-id"
	userEmailFlagName           = "user-email"
	accountRoleFlagName         = "account-role"
	namespacePermissionFlagName = "namespace-permission"
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
	namespacePermissions []string,
	accountRole string,
) error {
	if len(accountRole) == 0 {
		return errors.New("account role required for inviting new users")
	}

	// the role ids to invite the users for
	var roleIDs []string

	// first get the required account role
	role, err := getAccountRole(c.ctx, c.client, accountRole)
	if err != nil {
		return err
	}
	roleIDs = append(roleIDs, role.GetId())

	// get any optional namespace permissions
	if len(namespacePermissions) > 0 {
		npm, err := toUserNamespacePermissionsMap(namespacePermissions)
		if err != nil {
			return err
		}
		nsRoles, err := getNamespaceRolesFromMap(c.ctx, c.client, npm)
		if err != nil {
			return err
		}
		for _, nsRole := range nsRoles {
			roleIDs = append(roleIDs, nsRole.GetId())
		}
	}

	// Invite users to given roles
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

func (c *UserClient) setAccountRole(
	ctx *cli.Context,
	userID string,
	userEmail string,
	accountRole string,
) error {
	user, userRoles, err := c.getUserAndRoles(userID, userEmail)
	if err != nil {
		return err
	}
	accountRoleToSet, err := getAccountRole(c.ctx, c.client, accountRole)
	if err != nil {
		return err
	}
	for i := range userRoles {
		if userRoles[i].Id == accountRoleToSet.Id {
			return fmt.Errorf("user already has '%s' account role", accountRoleToSet.Id)
		}
	}
	// check if this is the global admin role, and replace all existing roles
	if accountRoleToSet.Spec.AccountRole.ActionGroup == auth.ACCOUNT_ACTION_GROUP_ADMIN {
		// set the user account admin role
		y, err := ConfirmPrompt(ctx, "Setting admin role on user, please confirm")
		if err != nil || !y {
			return err
		}
		userRoles = []*auth.Role{accountRoleToSet}
	} else {
		for i := range userRoles {
			ur := userRoles[i]
			if ur.Type != auth.ROLE_TYPE_PREDEFINED {
				continue
			}
			// find the current admin role to replace
			ar := ur.Spec.AccountRole
			if ar != nil && ar.ActionGroup != auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
				// only swap the current admin role
				userRoles[i] = accountRoleToSet
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
		return fmt.Errorf("unable to update user's namespace permission: %w", err)
	}
	return PrintProto(resp.GetRequestStatus())
}

func (c *UserClient) setNamespacePermissions(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespacePermissions []string,
) error {
	npm, err := toNamespacePermissionsMap(namespacePermissions)
	if err != nil {
		return err
	}
	for namespace, permission := range npm {
		ag, err := toNamespaceActionGroup(permission)
		if err != nil {
			return err
		}
		if err := c.updateUserNamespacePermissions(ctx, userID, userEmail, namespace, ag); err != nil {
			return err
		}
	}
	return nil
}

func (c *UserClient) deleteNamespacePermission(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespaces []string,
) error {
	for _, ns := range namespaces {
		if err := c.updateUserNamespacePermissions(ctx, userID, userEmail, ns, auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED); err != nil {
			return err
		}
	}
	return nil
}

func toNamespacePermissionsMap(keyValues []string) (map[string]string, error) {
	res := map[string]string{}
	for _, kv := range keyValues {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid namespace permission \"%s\" must be of format: \"namespace=permission\"", kv)
		}

		namespace := parts[0]
		actionGroupValue := parts[1]

		if len(namespace) == 0 {
			return nil, errors.New("namespace must not be empty in namespace permission")
		}

		res[namespace] = actionGroupValue
	}
	return res, nil
}

func NewUserCommand(getUserClientFn GetUserClientFn) (CommandOut, error) {
	var c *UserClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "user",
			Aliases: []string{"u"},
			Usage:   "User management operations",
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
							Name:    NamespaceFlagName,
							Usage:   "List users that have permissions to the namespace",
							Aliases: []string{"n"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listUsers(ctx.String(NamespaceFlagName))
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
							Aliases:  []string{"e"},
							Required: true,
						},
						&cli.StringFlag{
							Name:     accountRoleFlagName,
							Usage:    fmt.Sprintf("The account role to set on the user; valid types are: %v", accountActionGroups),
							Aliases:  []string{"ar"},
							Required: true,
						},
						&cli.StringSliceFlag{
							Name:    namespacePermissionFlagName,
							Usage:   fmt.Sprintf("Flag can be used multiple times; value must be \"namespace=permission\"; valid types are: %v", namespaceActionGroups),
							Aliases: []string{"p"},
						},
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.inviteUsers(
							ctx,
							ctx.StringSlice(userEmailFlagName),
							ctx.StringSlice(namespacePermissionFlagName),
							ctx.String(accountRoleFlagName),
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
					Name:    "resend-invite",
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
					Name:    "roles",
					Usage:   "User role and permission settings",
					Aliases: []string{"r"},
					Subcommands: []*cli.Command{
						{
							Name:    "list",
							Usage:   "List roles and permissions for a user",
							Aliases: []string{"l"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
							},
							Action: func(ctx *cli.Context) error {
								_, roles, err := c.getUserAndRoles(ctx.String(userIDFlagName), ctx.String(userEmailFlagName))
								if err != nil {
									return err
								}
								var res []proto.Message
								for _, roleRes := range roles {
									res = append(res, roleRes)
								}
								return PrintProtoSlice("Roles", res)
							},
						},
						{
							Name:    "set-account-role",
							Usage:   "Set account role for a user",
							Aliases: []string{"sar"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringFlag{
									Name:     accountRoleFlagName,
									Usage:    fmt.Sprintf("The account role to set on the user; valid types are: %v", accountActionGroups),
									Required: true,
									Aliases:  []string{"ar"},
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.setAccountRole(
									ctx,
									ctx.String(userIDFlagName),
									ctx.String(userEmailFlagName),
									ctx.String(accountRoleFlagName),
								)
							},
						},

						{
							Name:    "set-namespace-permissions",
							Usage:   "Set namespace permissions for a user",
							Aliases: []string{"snp"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringSliceFlag{
									Name:     namespacePermissionFlagName,
									Usage:    fmt.Sprintf("Flag can be used multiple times; value must be \"namespace=permission\"; valid types are: %v", namespaceActionGroups),
									Aliases:  []string{"p"},
									Required: true,
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.setNamespacePermissions(
									ctx,
									ctx.String(userIDFlagName),
									ctx.String(userEmailFlagName),
									ctx.StringSlice(namespacePermissionFlagName),
								)
							},
						},
						{
							Name:    "delete-namespace-permission",
							Usage:   "Delete namespace permissions for a user",
							Aliases: []string{"dnp"},
							Flags: []cli.Flag{
								userIDFlag,
								userEmailFlag,
								RequestIDFlag,
								ResourceVersionFlag,
								&cli.StringSliceFlag{
									Name:     NamespaceFlagName,
									Usage:    "The namespace to delete user permissions from",
									Required: true,
									Aliases:  []string{"n"},
								},
							},
							Action: func(ctx *cli.Context) error {
								return c.deleteNamespacePermission(
									ctx,
									ctx.String(userIDFlagName),
									ctx.String(userEmailFlagName),
									ctx.StringSlice(NamespaceFlagName),
								)
							},
						},
					},
				},
			},
		},
	}, nil
}
