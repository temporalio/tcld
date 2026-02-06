package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
)

const (
	userIDFlagName              = "user-id"
	userEmailFlagName           = "user-email"
	accountRoleFlagName         = "account-role"
	namespacePermissionFlagName = "namespace-permission"
	pageTokenFlagName           = "page-token"
	pageSizeFlagName            = "page-size"
)

var (
	userIDFlag = &cli.StringFlag{
		Name:    userIDFlagName,
		Usage:   "The user id",
		Aliases: []string{"id"},
	}
	userEmailFlag = &cli.StringFlag{
		Name:    userEmailFlagName,
		Usage:   "The user email address of the user",
		Aliases: []string{"e"},
	}
)

type (
	UserClient struct {
		client authservice.AuthServiceClient
		ctx    context.Context
	}
	GetUserClientFn func(ctx *cli.Context) (*UserClient, error)
)

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
	pageToken string,
	pageSize int,
) error {
	getUsersRes, err := c.client.GetUsers(c.ctx, &authservice.GetUsersRequest{
		PageToken: pageToken,
		PageSize:  int32(pageSize),
		Namespace: namespace,
	})
	if err != nil {
		return fmt.Errorf("unable to get users: %v", err)
	}
	var res []*auth.UserWrapper
	for _, u := range getUsersRes.Users {
		roles, err := c.getUserRoles(u.Id)
		if err != nil {
			return fmt.Errorf("unable to get users: %v", err)
		}
		res = append(res, toUserWrapper(u, roles))
	}
	return PrintProto(&auth.GetUsersResponseWrapper{
		Users:         res,
		NextPageToken: getUsersRes.NextPageToken,
	})
}

func (c *UserClient) getUser(userID, userEmail string) (*auth.User, error) {
	if userID == "" && userEmail == "" {
		return nil, fmt.Errorf("exactly one of user-id or user-email must be set")
	}

	if userID != "" && userEmail != "" {
		return nil, fmt.Errorf("exactly one of user-id or user-email must be set")
	}
	res, err := c.client.GetUser(c.ctx, &authservice.GetUserRequest{
		UserId:    userID,
		UserEmail: userEmail,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get user: %v", err)
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
	roles, err := c.getUserRoles(user.Id)
	return user, roles, err
}

func (c *UserClient) getUserRoles(userID string) ([]*auth.Role, error) {
	var pageToken string
	var roles []*auth.Role
	for {
		res, err := c.client.GetRoles(c.ctx, &authservice.GetRolesRequest{
			PageToken: pageToken,
			UserId:    userID,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to get roles: %v", err)
		}
		roles = append(roles, res.Roles...)
		// Check if we should continue paging
		pageToken = res.NextPageToken
		if len(pageToken) == 0 {
			break
		}
	}

	return roles, nil
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
		npm, err := toNamespacePermissionsMap(namespacePermissions)
		if err != nil {
			return err
		}
		nsRoles, err := getNamespaceRolesBatch(c.ctx, c.client, npm)
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
	u, err := c.getUser(userID, userEmail)
	if err != nil {
		return err
	}
	req := &authservice.DeleteUserRequest{
		UserId:          u.Id,
		ResourceVersion: ctx.String(ResourceVersionFlagName),
		RequestId:       ctx.String(RequestIDFlagName),
	}
	if req.ResourceVersion == "" {
		req.ResourceVersion = u.ResourceVersion
	}
	resp, err := c.client.DeleteUser(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to delete user: %w", err)
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
		if isNothingChangedErr(ctx, err) {
			return nil
		}
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
	var newRoleIDs []string
	accountRoleToSet, err := getAccountRole(c.ctx, c.client, accountRole)
	if err != nil {
		return err
	}
	if accountRoleToSet.Spec.AccountRole.ActionGroup == auth.ACCOUNT_ACTION_GROUP_ADMIN {
		// set the user account admin role
		y, err := ConfirmPrompt(ctx, "Setting admin role on user. All existing namespace permissions will be replaced, please confirm")
		if err != nil {
			return err
		}
		if !y {
			fmt.Println("operation canceled")
			return nil
		}
		// ensure we overwrite all existing roles since the global admin role has permissions to everything
		newRoleIDs = []string{accountRoleToSet.Id}
	} else {
		for _, r := range userRoles {
			// skip over existing predefined account role
			if r.Type == auth.ROLE_TYPE_PREDEFINED && r.Spec.AccountRole != nil && r.Spec.AccountRole.ActionGroup != auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
				continue
			} else {
				newRoleIDs = append(newRoleIDs, r.Id)
			}
		}
		newRoleIDs = append(newRoleIDs, accountRoleToSet.Id)
	}
	user.Spec.Roles = newRoleIDs
	return c.performUpdate(ctx, user)
}

func (c *UserClient) setNamespacePermissions(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespacePermissions []string,
) error {
	user, userRoles, err := c.getUserAndRoles(userID, userEmail)
	if err != nil {
		return err
	}
	var newRoleIDs []string
	for _, r := range userRoles {
		// skip over existing predefined namespace roles
		if r.Type == auth.ROLE_TYPE_PREDEFINED && len(r.Spec.NamespaceRoles) > 0 {
			continue
		} else {
			newRoleIDs = append(newRoleIDs, r.Id)
		}
	}
	if len(namespacePermissions) == 0 {
		y, err := ConfirmPrompt(ctx, "Looks like you are about to remove all namespace permissions, please confirm")
		if err != nil {
			return err
		}
		if !y {
			fmt.Println("operation canceled")
			return nil
		}
	} else {
		// collect the namespace roles and update user
		npm, err := toNamespacePermissionsMap(namespacePermissions)
		if err != nil {
			return err
		}
		nsRoles, err := getNamespaceRolesBatch(c.ctx, c.client, npm)
		if err != nil {
			return err
		}
		for _, nsRole := range nsRoles {
			newRoleIDs = append(newRoleIDs, nsRole.Id)
		}
	}
	user.Spec.Roles = newRoleIDs
	return c.performUpdate(ctx, user)
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
		if len(actionGroupValue) == 0 {
			return nil, errors.New("permission must not be empty in namespace permission")
		}

		if _, err := toNamespaceActionGroup(actionGroupValue); err != nil {
			return nil, fmt.Errorf("invalid namespace permission \"%s\" must be one of: %s", actionGroupValue, namespaceActionGroups)
		}

		res[namespace] = actionGroupValue
	}
	return res, nil
}

func toUserWrapper(u *auth.User, roles []*auth.Role) *auth.UserWrapper {
	p := &auth.UserWrapper{
		Id:              u.Id,
		ResourceVersion: u.ResourceVersion,
		Spec: &auth.UserSpecWrapper{
			Email: u.Spec.Email,
		},
		State:            u.State,
		RequestId:        u.RequestId,
		Invitation:       u.Invitation,
		CreatedTime:      u.CreatedTime,
		LastModifiedTime: u.LastModifiedTime,
	}
	for _, r := range roles {
		if r.Type == auth.ROLE_TYPE_PREDEFINED &&
			r.Spec.AccountRole != nil &&
			r.Spec.AccountRole.ActionGroup != auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
			p.Spec.AccountRole = auth.AccountRole{
				Id:   r.Id,
				Role: r.Spec.AccountRole.ActionGroup.String(),
			}
		} else if r.Type == auth.ROLE_TYPE_PREDEFINED &&
			r.Spec.NamespaceRoles != nil &&
			len(r.Spec.NamespaceRoles) > 0 {
			for _, nr := range r.Spec.NamespaceRoles {
				p.Spec.NamespacePermissions = append(p.Spec.NamespacePermissions, auth.NamespacePermission{
					Id:         r.Id,
					Namespace:  nr.Namespace,
					Permission: nr.ActionGroup.String(),
				})
			}
		}
	}
	return p
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
						&cli.StringFlag{
							Name:    pageTokenFlagName,
							Usage:   "Page token for paging list users request",
							Aliases: []string{"p"},
						},
						&cli.IntFlag{
							Name:    pageSizeFlagName,
							Usage:   "Page size for paging list users request",
							Value:   10,
							Aliases: []string{"s"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listUsers(ctx.String(NamespaceFlagName), ctx.String(pageTokenFlagName), ctx.Int(pageSizeFlagName))
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
						u, roles, err := c.getUserAndRoles(ctx.String(userIDFlagName), ctx.String(userEmailFlagName))
						if err != nil {
							return err
						}
						return PrintProto(toUserWrapper(u, roles))
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
					Usage:   "Set entirely new set of namespace permissions for a user",
					Aliases: []string{"snp"},
					Flags: []cli.Flag{
						userIDFlag,
						userEmailFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.StringSliceFlag{
							Name:    namespacePermissionFlagName,
							Usage:   fmt.Sprintf("Flag can be used multiple times; value must be \"namespace=permission\"; valid types are: %v", namespaceActionGroups),
							Aliases: []string{"p"},
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
			},
		},
	}, nil
}
