package app

import (
	"context"
	"errors"
	"fmt"
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
	permissionFlagName          = "permission"
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
	NamespacePermission struct {
		Namespace  string `json:"namespace"`
		Permission string `json:"permission"`
	}
	UserPermissions struct {
		AccountRole          string                `json:"accountRole"`
		NamespacePermissions []NamespacePermission `json:"namespacePermissions"`
	}
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
) error {
	totalRes := &authservice.GetUsersResponse{}
	pageToken := ""
	for {
		res, err := c.client.GetUsers(c.ctx, &authservice.GetUsersRequest{
			PageToken: pageToken,
			Namespace: namespace,
		})
		if err != nil {
			return fmt.Errorf("unable to get users: %v", err)
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
	var pageToken string
	var roles []*auth.Role
	for {
		res, err := c.client.GetRoles(c.ctx, &authservice.GetRolesRequest{
			PageToken: pageToken,
			UserId:    user.Id,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get roles: %v", err)
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
	// collect the namespace roles and update user
	npm, err := toNamespacePermissionsMap(namespacePermissions)
	if err != nil {
		return err
	}
	if len(npm) == 0 {
		y, err := ConfirmPrompt(ctx, "Looks like you are about to remove all namespace permissions, please confirm")
		if err != nil {
			return err
		}
		if !y {
			fmt.Println("operation canceled")
			return nil
		}
	}
	nsRoles, err := getNamespaceRolesBatch(c.ctx, c.client, npm)
	if err != nil {
		return err
	}
	for _, nsRole := range nsRoles {
		newRoleIDs = append(newRoleIDs, nsRole.Id)
	}
	user.Spec.Roles = newRoleIDs
	return c.performUpdate(ctx, user)
}

func (c *UserClient) updateNamespacePermission(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespace string,
	permission string,
) error {
	ag, err := toNamespaceActionGroup(permission)
	if err != nil {
		return err
	}
	return c.updateUserNamespacePermissions(ctx, userID, userEmail, namespace, ag)
}

func (c *UserClient) deleteNamespacePermission(
	ctx *cli.Context,
	userID string,
	userEmail string,
	namespace string,
) error {
	return c.updateUserNamespacePermissions(ctx, userID, userEmail, namespace, auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED)
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

		res[namespace] = actionGroupValue
	}
	return res, nil
}

func toUserPermissions(roles []*auth.Role) UserPermissions {
	var res UserPermissions
	for _, role := range roles {
		if role.Type == auth.ROLE_TYPE_PREDEFINED {
			if role.Spec.AccountRole != nil && role.Spec.AccountRole.ActionGroup != auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
				res.AccountRole = auth.AccountActionGroup_name[int32(role.Spec.AccountRole.ActionGroup)]
			}
			if len(role.Spec.NamespaceRoles) > 0 {
				for _, nr := range role.Spec.NamespaceRoles {
					res.NamespacePermissions = append(
						res.NamespacePermissions,
						NamespacePermission{
							Namespace:  nr.Namespace,
							Permission: auth.NamespaceActionGroup_name[int32(nr.ActionGroup)],
						},
					)
				}
			}
		}
	}
	return res
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
					Name:    "get-roles-and-permissions",
					Usage:   "Get roles and permissions for a user",
					Aliases: []string{"grp"},
					Flags: []cli.Flag{
						userIDFlag,
						userEmailFlag,
					},
					Action: func(ctx *cli.Context) error {
						_, roles, err := c.getUserAndRoles(ctx.String(userIDFlagName), ctx.String(userEmailFlagName))
						if err != nil {
							return err
						}
						res := toUserPermissions(roles)
						return PrintObj(res)
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
					Name:    "update-namespace-permission",
					Usage:   "Add new or update existing namespace permission for a user",
					Aliases: []string{"unp"},
					Flags: []cli.Flag{
						userIDFlag,
						userEmailFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.StringFlag{
							Name:     NamespaceFlagName,
							Usage:    "The namespace to add user permissions for",
							Required: true,
							Aliases:  []string{"n"},
						},
						&cli.StringFlag{
							Name:     permissionFlagName,
							Usage:    fmt.Sprintf("Namespace permission; valid types are: %v", namespaceActionGroups),
							Aliases:  []string{"p"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.updateNamespacePermission(
							ctx,
							ctx.String(userIDFlagName),
							ctx.String(userEmailFlagName),
							ctx.String(NamespaceFlagName),
							ctx.String(permissionFlagName),
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
						&cli.StringFlag{
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
							ctx.String(NamespaceFlagName),
						)
					},
				},
			},
		},
	}, nil
}
