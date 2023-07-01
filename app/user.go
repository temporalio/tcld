package app

import (
	"context"
	"errors"
	"fmt"
	"os"

	"strings"

	"github.com/cjrd/allocate"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
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
) (*request.RequestStatus, error) {
	if len(accountRole) == 0 {
		return nil, errors.New("account role required for inviting new users")
	}

	// the role ids to invite the users for
	var roleIDs []string

	// first get the required account role
	role, err := getAccountRole(c.ctx, c.client, accountRole)
	if err != nil {
		return nil, err
	}
	roleIDs = append(roleIDs, role.GetId())

	// get any optional namespace permissions
	if len(namespacePermissions) > 0 {
		npm, err := toNamespacePermissionsMap(namespacePermissions)
		if err != nil {
			return nil, err
		}
		nsRoles, err := getNamespaceRolesBatch(c.ctx, c.client, npm)
		if err != nil {
			return nil, err
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
		return nil, fmt.Errorf("unable to invite users: %w", err)
	}
	return resp.GetRequestStatus(), nil
}

func (c *UserClient) resendInvitation(
	ctx *cli.Context,
	userID string,
	userEmail string,
) (*request.RequestStatus, error) {
	user, err := c.getUser(userID, userEmail)
	if err != nil {
		return nil, err
	}
	req := &authservice.ResendUserInviteRequest{
		UserId:    user.Id,
		RequestId: ctx.String(RequestIDFlagName),
	}
	resp, err := c.client.ResendUserInvite(c.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("unable to resend invitation for user: %w", err)
	}
	return resp.GetRequestStatus(), nil
}

func (c *UserClient) deleteUser(
	ctx *cli.Context,
	userID string,
	userEmail string,
) (*request.RequestStatus, error) {
	u, err := c.getUser(userID, userEmail)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("unable to delete user: %w", err)
	}
	return resp.GetRequestStatus(), nil
}

func (c *UserClient) performUpdate(ctx *cli.Context, user *auth.User) (*request.RequestStatus, error) {
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
		return nil, fmt.Errorf("unable to update user: %w", err)
	}
	return resp.GetRequestStatus(), nil
}

func (c *UserClient) setAccountRole(
	ctx *cli.Context,
	userID string,
	userEmail string,
	accountRole string,
) (*request.RequestStatus, error) {
	user, userRoles, err := c.getUserAndRoles(userID, userEmail)
	if err != nil {
		return nil, err
	}
	var newRoleIDs []string
	accountRoleToSet, err := getAccountRole(c.ctx, c.client, accountRole)
	if err != nil {
		return nil, err
	}
	if accountRoleToSet.Spec.AccountRole.ActionGroup == auth.ACCOUNT_ACTION_GROUP_ADMIN {
		// set the user account admin role
		y, err := ConfirmPrompt(ctx, "Setting admin role on user. All existing namespace permissions will be replaced, please confirm")
		if err != nil {
			return nil, err
		}
		if !y {
			fmt.Println("operation canceled")
			return nil, nil
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
) (*request.RequestStatus, error) {
	user, userRoles, err := c.getUserAndRoles(userID, userEmail)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		if !y {
			fmt.Println("operation canceled")
			return nil, nil
		}
	} else {
		// collect the namespace roles and update user
		npm, err := toNamespacePermissionsMap(namespacePermissions)
		if err != nil {
			return nil, err
		}
		nsRoles, err := getNamespaceRolesBatch(c.ctx, c.client, npm)
		if err != nil {
			return nil, err
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

func (c *UserClient) fromUserSpecWrapper(wrapper *auth.UserSpecWrapper) (*auth.UserSpec, error) {

	var roleSpec = make([]*auth.RoleSpec, 0)
	roleSpec = append(roleSpec, &auth.RoleSpec{
		AccountRole: &auth.AccountRoleSpec{
			ActionGroup: auth.AccountActionGroup(auth.AccountActionGroup_value[wrapper.AccountRole.Role]),
		},
	})
	for i := range wrapper.NamespacePermissions {
		roleSpec = append(roleSpec, &auth.RoleSpec{
			NamespaceRoles: []*auth.NamespaceRoleSpec{
				&auth.NamespaceRoleSpec{
					Namespace:   wrapper.NamespacePermissions[i].Namespace,
					ActionGroup: auth.NamespaceActionGroup(auth.NamespaceActionGroup_value[wrapper.NamespacePermissions[i].Permission]),
				},
			},
		})
	}
	res, err := c.client.GetRolesByPermissions(c.ctx, &authservice.GetRolesByPermissionsRequest{
		Specs: roleSpec,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get roles by permission: %v", err)
	}
	var roles = make([]string, len(res.Roles))
	for i := range res.Roles {
		roles[i] = res.Roles[i].Id
	}
	return &auth.UserSpec{
		Email: wrapper.Email,
		Roles: roles,
	}, nil

}

func readUserSpecificationWrapper(ctx *cli.Context) (*auth.UserSpecWrapper, error) {
	spec := ctx.String(SpecFlagName)
	if spec == "" {
		if ctx.Path(SpecFileFlagName) != "" {
			data, err := os.ReadFile(ctx.Path(SpecFileFlagName))
			if err != nil {
				return nil, err
			}
			spec = string(data)
		}
	}
	if spec == "" {
		return nil, fmt.Errorf("no specification provided")
	}
	var specProto auth.UserSpecWrapper
	unmarshaler := jsonpb.Unmarshaler{}
	err := unmarshaler.Unmarshal(strings.NewReader(spec), &specProto)
	if err != nil {
		return nil, err
	}
	return &specProto, nil
}

func NewUserCommand(getUserClientFn GetUserClientFn, getRequestClientFn GetRequestClientFn) (CommandOut, error) {
	var (
		uc *UserClient
		rc *RequestClient
	)
	return CommandOut{
		Command: &cli.Command{
			Name:    "user",
			Aliases: []string{"u"},
			Usage:   "User management operations",
			Before: func(ctx *cli.Context) error {
				var err error
				uc, err = getUserClientFn(ctx)
				if err != nil {
					return err
				}
				rc, err = getRequestClientFn(ctx)
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
						return uc.listUsers(ctx.String(NamespaceFlagName), ctx.String(pageTokenFlagName), ctx.Int(pageSizeFlagName))
					},
				},
				{
					Name:    "get",
					Usage:   "Get user information",
					Aliases: []string{"g"},
					Flags: []cli.Flag{
						userIDFlag,
						userEmailFlag,
						&cli.BoolFlag{
							Name:  "spec",
							Usage: "Get the spec of the user",
						},
					},
					Action: func(ctx *cli.Context) error {
						u, roles, err := uc.getUserAndRoles(ctx.String(userIDFlagName), ctx.String(userEmailFlagName))
						if err != nil {
							return err
						}
						user := toUserWrapper(u, roles)
						if ctx.Bool("spec") {
							return PrintProto(user.Spec)
						}
						return PrintProto(user)
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
						WaitForRequestFlag,
						RequestTimeoutFlag,
					},
					Action: func(ctx *cli.Context) error {
						status, err := uc.inviteUsers(
							ctx,
							ctx.StringSlice(userEmailFlagName),
							ctx.StringSlice(namespacePermissionFlagName),
							ctx.String(accountRoleFlagName),
						)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "invite users", status)
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
						WaitForRequestFlag,
						RequestTimeoutFlag,
					},
					Action: func(ctx *cli.Context) error {
						status, err := uc.resendInvitation(
							ctx,
							ctx.String(userIDFlagName),
							ctx.String(userEmailFlagName),
						)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "resend user invite", status)
					},
				},
				{
					Name:    "apply",
					Usage:   "Apply specification to user",
					Aliases: []string{"a"},
					Flags: []cli.Flag{
						userIDFlag,
						userEmailFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						WaitForRequestFlag,
						RequestTimeoutFlag,
						&cli.StringFlag{
							Name:  SpecFlagName,
							Usage: "the specification in JSON format to update the namespace to",
						},
						&cli.PathFlag{
							Name:  SpecFileFlagName,
							Usage: "the path to the file containing the specification in JSON format to update the namespace to",
						},
					},
					Action: func(ctx *cli.Context) error {
						specWrapper, err := readUserSpecificationWrapper(ctx)
						if err != nil {
							return err
						}
						u, err := uc.getUser(ctx.String(userIDFlagName), ctx.String(userEmailFlagName))
						if err != nil {
							return err
						}

						spec, err := uc.fromUserSpecWrapper(specWrapper)
						if err != nil {
							return err
						}
						// allocate the pointers in the specs to get a correct diff
						allocate.MustZero(u.Spec)
						allocate.MustZero(spec)
						diff, err := ProtoDiff(u.Spec, spec)
						if err != nil {
							return err
						}
						if diff == "" {
							fmt.Printf("nothing to change\n")
							return nil
						}
						fmt.Printf("Changes: \n%s\n", diff)
						yes, err := ConfirmPrompt(ctx, fmt.Sprintf("Confirm changes for user with id='%s' and email='%s'", u.Id, u.Spec.Email))
						if err != nil {
							return err
						}
						if !yes {
							fmt.Printf("cancelled\n")
							return nil
						}
						u.Spec = spec
						status, err := uc.performUpdate(ctx, u)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "update namespace", status)
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
						WaitForRequestFlag,
						RequestTimeoutFlag,
					},
					Action: func(ctx *cli.Context) error {
						status, err := uc.deleteUser(
							ctx,
							ctx.String(userIDFlagName),
							ctx.String(userEmailFlagName),
						)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "delete user", status)
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
						WaitForRequestFlag,
						RequestTimeoutFlag,
						&cli.StringFlag{
							Name:     accountRoleFlagName,
							Usage:    fmt.Sprintf("The account role to set on the user; valid types are: %v", accountActionGroups),
							Required: true,
							Aliases:  []string{"ar"},
						},
					},
					Action: func(ctx *cli.Context) error {
						status, err := uc.setAccountRole(
							ctx,
							ctx.String(userIDFlagName),
							ctx.String(userEmailFlagName),
							ctx.String(accountRoleFlagName),
						)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "set account role", status)
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
						status, err := uc.setNamespacePermissions(
							ctx,
							ctx.String(userIDFlagName),
							ctx.String(userEmailFlagName),
							ctx.StringSlice(namespacePermissionFlagName),
						)
						if err != nil {
							return err
						}
						return rc.HandleRequestStatus(ctx, "set namespace permissions", status)
					},
				},
			},
		},
	}, nil
}
