package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	cloudsvc "github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/identity/v1"

	"github.com/urfave/cli/v2"
)

const (
	groupIDFlagName       = "group-id"
	namespaceRoleFlagName = "namespace-role"
)

type (
	UserGroupClient struct {
		client     cloudsvc.CloudServiceClient
		authClient authservice.AuthServiceClient
		ctx        context.Context
	}

	GetGroupClientFn func(ctx *cli.Context) (*UserGroupClient, error)
)

// GetUserGroupClient builds a group client with cloud services connection and auth client
func GetUserGroupClient(ctx *cli.Context) (*UserGroupClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &UserGroupClient{
		client:     cloudsvc.NewCloudServiceClient(conn),
		authClient: authservice.NewAuthServiceClient(conn),
		ctx:        ct,
	}, nil
}

// listGroups lists the groups for the current user using the cloud services API
func (c *UserGroupClient) listGroups(
	pageToken string,
	pageSize int,
) error {
	groups, err := c.client.GetUserGroups(c.ctx, &cloudsvc.GetUserGroupsRequest{
		PageToken: pageToken,
		PageSize:  int32(pageSize),
	})

	if err != nil {
		return err
	}

	return PrintProto(groups)
}

// getGroup gets a group by ID using the cloud services API
func (c *UserGroupClient) getGroup(_ *cli.Context, groupID string) error {
	group, err := c.client.GetUserGroup(c.ctx, &cloudsvc.GetUserGroupRequest{
		GroupId: groupID,
	})
	if err != nil {
		return err
	}
	return PrintProto(group)
}

// accountRoleToAccess maps a string role to an identity.AccountAccess
func accountRoleToAccess(role string) *identity.AccountAccess {
	switch role {
	case "admin":
		return &identity.AccountAccess{
			Role: identity.ROLE_ADMIN,
		}
	case "read":
		return &identity.AccountAccess{
			Role: identity.ROLE_READ,
		}
	case "developer":
		return &identity.AccountAccess{
			Role: identity.ROLE_DEVELOPER,
		}
	case "owner":
		return &identity.AccountAccess{
			Role: identity.ROLE_OWNER,
		}
	case "financeadmin":
		return &identity.AccountAccess{
			Role: identity.ROLE_FINANCE_ADMIN,
		}
	case "none":
		return &identity.AccountAccess{
			Role: identity.ROLE_UNSPECIFIED,
		}
	}
	return nil
}

// nsRoleToAccess maps a string role to a namespace name and identity.NamespaceAccess
func nsRoleToAccess(role string) (string, *identity.NamespaceAccess) {
	idx := strings.LastIndex(role, "-")
	if idx == -1 {
		return "", nil
	}

	ns := role[:idx]
	rolePart := role[idx+1:]

	switch rolePart {
	case "admin":
		return ns, &identity.NamespaceAccess{
			Permission: identity.PERMISSION_ADMIN,
		}
	case "read":
		return ns, &identity.NamespaceAccess{
			Permission: identity.PERMISSION_READ,
		}
	case "write":
		return ns, &identity.NamespaceAccess{
			Permission: identity.PERMISSION_WRITE,
		}
	}
	return ns, nil
}

// setAccess sets the access for a group using the cloud services API
func (c *UserGroupClient) setAccess(ctx *cli.Context, groupID string, accountRole string, nsRoles []string) error {
	group, err := c.client.GetUserGroup(c.ctx, &cloudsvc.GetUserGroupRequest{
		GroupId: groupID,
	})
	if err != nil {
		return err
	}
	aRole := accountRoleToAccess(accountRole)
	if aRole == nil {
		return cli.Exit(fmt.Sprintf("Invalid account role: %s", accountRole), 1)
	}
	group.Group.Spec.Access.AccountAccess = aRole
	if accountRole == "none" {
		group.Group.Spec.Access.AccountAccess = nil
	}

	nsAccess := map[string]*identity.NamespaceAccess{}
	for _, role := range nsRoles {
		name, access := nsRoleToAccess(role)
		if access == nil {
			return cli.Exit(fmt.Sprintf("Invalid namespace role: %s", role), 1)
		}
		nsAccess[name] = access
	}

	group.Group.Spec.Access.NamespaceAccesses = nsAccess

	req := &cloudsvc.UpdateUserGroupRequest{
		GroupId:         groupID,
		Spec:            group.Group.Spec,
		ResourceVersion: group.Group.ResourceVersion,
	}

	resp, err := c.client.UpdateUserGroup(c.ctx, req)
	if err != nil {
		if isNothingChangedErr(ctx, err) {
			return nil
		}
		return err
	}

	return PrintProto(resp.GetAsyncOperation())
}

// createGroup creates a new user group with the specified display name and account role
func (c *UserGroupClient) createGroup(_ *cli.Context, displayName string, accountRole string) error {
	aRole := accountRoleToAccess(accountRole)
	if aRole == nil {
		return cli.Exit(fmt.Sprintf("Invalid account role: %s", accountRole), 1)
	}

	spec := &identity.UserGroupSpec{
		DisplayName: displayName,
		Access: &identity.Access{
			AccountAccess: aRole,
		},
		GroupType: &identity.UserGroupSpec_CloudGroup{
			CloudGroup: &identity.CloudGroupSpec{},
		},
	}

	resp, err := c.client.CreateUserGroup(c.ctx, &cloudsvc.CreateUserGroupRequest{
		Spec: spec,
	})
	if err != nil {
		return err
	}

	return PrintProto(resp.GetAsyncOperation())
}

// getUserIDByEmail gets a user ID by email using the auth service API
func (c *UserGroupClient) getUserIDByEmail(email string) (string, error) {
	res, err := c.authClient.GetUser(c.ctx, &authservice.GetUserRequest{
		UserEmail: email,
	})
	if err != nil {
		return "", fmt.Errorf("unable to get user: %w", err)
	}
	if res.User == nil || res.User.Id == "" {
		return "", fmt.Errorf("user not found for email: %s", email)
	}
	return res.User.Id, nil
}

// addUsersToGroup adds users to a group using the cloud services API
func (c *UserGroupClient) addUsersToGroup(ctx *cli.Context, groupID string, emails []string) error {
	for _, email := range emails {
		userID, err := c.getUserIDByEmail(email)
		if err != nil {
			return fmt.Errorf("unable to add user %s to group: %w", email, err)
		}

		req := &cloudsvc.AddUserGroupMemberRequest{
			GroupId: groupID,
			MemberId: &identity.UserGroupMemberId{
				MemberType: &identity.UserGroupMemberId_UserId{
					UserId: userID,
				},
			},
			AsyncOperationId: ctx.String(RequestIDFlagName),
		}

		resp, err := c.client.AddUserGroupMember(c.ctx, req)
		if err != nil {
			return fmt.Errorf("unable to add user %s to group: %w", email, err)
		}

		if err := PrintProto(resp.GetAsyncOperation()); err != nil {
			return err
		}
	}
	return nil
}

// removeUsersFromGroup removes users from a group using the cloud services API
func (c *UserGroupClient) removeUsersFromGroup(ctx *cli.Context, groupID string, emails []string) error {
	for _, email := range emails {
		userID, err := c.getUserIDByEmail(email)
		if err != nil {
			return fmt.Errorf("unable to remove user %s from group: %w", email, err)
		}

		req := &cloudsvc.RemoveUserGroupMemberRequest{
			GroupId: groupID,
			MemberId: &identity.UserGroupMemberId{
				MemberType: &identity.UserGroupMemberId_UserId{
					UserId: userID,
				},
			},
			AsyncOperationId: ctx.String(RequestIDFlagName),
		}

		resp, err := c.client.RemoveUserGroupMember(c.ctx, req)
		if err != nil {
			return fmt.Errorf("unable to remove user %s from group: %w", email, err)
		}

		if err := PrintProto(resp.GetAsyncOperation()); err != nil {
			return err
		}
	}
	return nil
}

// listGroupMembers lists the members of a group using the cloud services API
func (c *UserGroupClient) listGroupMembers(
	pageToken string,
	pageSize int,
	groupID string,
) error {
	members, err := c.client.GetUserGroupMembers(c.ctx, &cloudsvc.GetUserGroupMembersRequest{
		PageToken: pageToken,
		PageSize:  int32(pageSize),
		GroupId:   groupID,
	})

	if err != nil {
		return err
	}

	return PrintProto(members)
}

// NewUserGroupCommand creates a new command for group management
func NewUserGroupCommand(GetGroupClientFn GetGroupClientFn) (CommandOut, error) {
	var c *UserGroupClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "user-group",
			Aliases: []string{"ug"},
			Usage:   "User group management operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = GetGroupClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:    "list",
					Usage:   "List groups",
					Aliases: []string{"l"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    pageTokenFlagName,
							Usage:   "list groups starting from this page token",
							Aliases: []string{"p"},
						},
						&cli.IntFlag{
							Name:    pageSizeFlagName,
							Usage:   "number of groups to list",
							Aliases: []string{"s"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listGroups(ctx.String(pageTokenFlagName), ctx.Int(pageSizeFlagName))
					},
				},
				{
					Name:    "get",
					Usage:   "Get group",
					Aliases: []string{"g"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    groupIDFlagName,
							Usage:   "group ID",
							Aliases: []string{"id"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.getGroup(ctx, ctx.String(groupIDFlagName))
					},
				},
				{
					Name:    "create",
					Usage:   "Create a new user group",
					Aliases: []string{"c"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "display-name",
							Usage:    "display name for the group",
							Required: true,
						},
						&cli.StringFlag{
							Name:     accountRoleFlagName,
							Usage:    "account role (admin, read, developer, owner, financeadmin, none)",
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.createGroup(ctx, ctx.String("display-name"), ctx.String(accountRoleFlagName))
					},
				},
				{
					Name:    "set-access",
					Usage:   "Set group access",
					Aliases: []string{"sa"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    groupIDFlagName,
							Usage:   "group ID",
							Aliases: []string{"id"},
						},
						&cli.StringFlag{
							Name:    accountRoleFlagName,
							Usage:   "account role",
							Aliases: []string{"ar"},
						},
						&cli.StringSliceFlag{
							Name:    namespaceRoleFlagName,
							Usage:   "namespace roles",
							Aliases: []string{"nr"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.setAccess(ctx, ctx.String(groupIDFlagName), ctx.String(accountRoleFlagName), ctx.StringSlice(namespaceRoleFlagName))
					},
				},
				{
					Name:    "add-users",
					Usage:   "Add users to a group",
					Aliases: []string{"au"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     groupIDFlagName,
							Usage:    "group ID",
							Aliases:  []string{"id"},
							Required: true,
						},
						&cli.StringSliceFlag{
							Name:     userEmailFlagName,
							Usage:    "The email address of the user, you can supply this flag multiple times to add multiple users in a single request",
							Aliases:  []string{"e"},
							Required: true,
						},
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.addUsersToGroup(ctx, ctx.String(groupIDFlagName), ctx.StringSlice(userEmailFlagName))
					},
				},
				{
					Name:    "remove-users",
					Usage:   "Remove users from a group",
					Aliases: []string{"ru"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     groupIDFlagName,
							Usage:    "group ID",
							Aliases:  []string{"id"},
							Required: true,
						},
						&cli.StringSliceFlag{
							Name:     userEmailFlagName,
							Usage:    "The email address of the user, you can supply this flag multiple times to remove multiple users in a single request",
							Aliases:  []string{"e"},
							Required: true,
						},
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.removeUsersFromGroup(ctx, ctx.String(groupIDFlagName), ctx.StringSlice(userEmailFlagName))
					},
				},
				{
					Name:    "list-members",
					Usage:   "List members of a group",
					Aliases: []string{"lm"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    groupIDFlagName,
							Usage:   "group ID",
							Aliases: []string{"id"},
						},
						&cli.StringFlag{
							Name:    pageTokenFlagName,
							Usage:   "list members starting from this page token",
							Aliases: []string{"p"},
						},
						&cli.IntFlag{
							Name:    pageSizeFlagName,
							Usage:   "number of members to list",
							Aliases: []string{"s"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listGroupMembers(ctx.String(pageTokenFlagName), ctx.Int(pageSizeFlagName), ctx.String(groupIDFlagName))
					},
				},
			},
		},
	}, nil
}
