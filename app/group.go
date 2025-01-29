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
	GroupClient struct {
		client     cloudsvc.CloudServiceClient
		authClient authservice.AuthServiceClient
		ctx        context.Context
	}

	GetGroupClientFn func(ctx *cli.Context) (*GroupClient, error)
)

// GetGroupClient builds a group client with cloud services connection and auth client
func GetGroupClient(ctx *cli.Context) (*GroupClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &GroupClient{
		client:     cloudsvc.NewCloudServiceClient(conn),
		authClient: authservice.NewAuthServiceClient(conn),
		ctx:        ct,
	}, nil
}

// listGroups lists the groups for the current user using the cloud services API
func (c *GroupClient) listGroups(
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
func (c *GroupClient) getGroup(_ *cli.Context, groupID string) error {
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
func (c *GroupClient) setAccess(_ *cli.Context, groupID string, accountRole string, nsRoles []string) error {
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
		return err
	}

	return PrintProto(resp.GetAsyncOperation())
}

// NewGroupCommand creates a new command for group management
func NewGroupCommand(GetGroupClientFn GetGroupClientFn) (CommandOut, error) {
	var c *GroupClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "group",
			Aliases: []string{"g"},
			Usage:   "Group management operations",
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
			},
		},
	}, nil
}
