package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
)

type RoleClient struct {
	client authservice.AuthServiceClient
	ctx    context.Context
}

type GetRoleClientFn func(ctx *cli.Context) (*RoleClient, error)

func GetRoleClient(ctx *cli.Context) (*RoleClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &RoleClient{
		client: authservice.NewAuthServiceClient(conn),
		ctx:    ct,
	}, nil
}

func (c *RoleClient) listRoles(userID string, namespace string) error {
	totalRes := &authservice.GetRolesResponse{}
	pageToken := ""
	for {
		res, err := c.client.GetRoles(c.ctx, &authservice.GetRolesRequest{
			PageToken: pageToken,
			UserId:    userID,
			Namespace: namespace,
		})
		if err != nil {
			return err
		}
		totalRes.Roles = append(totalRes.Roles, res.Roles...)
		// Check if we should continue paging
		pageToken = res.NextPageToken
		if len(pageToken) == 0 {
			return PrintProto(totalRes)
		}
	}
}

func getAccountActionGroups() []string {
	var rv []string
	for n, v := range auth.AccountActionGroup_value {
		if v != int32(auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED) {
			rv = append(rv, n)
		}
	}
	return rv
}

func toAccountActionGroup(permission string) (auth.AccountActionGroup, error) {
	p := strings.ToLower(strings.TrimSpace(permission))
	var ag auth.AccountActionGroup
	for n, v := range auth.AccountActionGroup_value {
		if strings.ToLower(n) == p {
			ag = auth.AccountActionGroup(v)
			break
		}
	}
	if ag == auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
		return auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED,
			fmt.Errorf("invalid permission: should be one of: %s", getAccountActionGroups())
	}
	return ag, nil
}

func getAccountRoles(ctx context.Context, client authservice.AuthServiceClient, permission string) (*authservice.GetRolesByPermissionsResponse, error) {
	p := strings.ToLower(strings.TrimSpace(permission))
	var ag auth.AccountActionGroup
	for n, v := range auth.AccountActionGroup_value {
		if strings.ToLower(n) == p {
			ag = auth.AccountActionGroup(v)
			break
		}
	}
	if ag == auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
		return nil, fmt.Errorf("invalid permission")
	}

	res, err := client.GetRolesByPermissions(ctx, &authservice.GetRolesByPermissionsRequest{
		Specs: []*auth.RoleSpec{{
			AccountRole: &auth.AccountRoleSpec{
				ActionGroup: ag,
			},
		}},
	})
	if err != nil {
		return nil, err
	}
	return res, nil

}

func (c *RoleClient) getAccountRoleByPermission(permission string) error {
	res, err := getAccountRoles(c.ctx, c.client, permission)
	if err != nil {
		return err
	}
	return PrintProto(res)
}

func getNamespaceActionGroups() []string {
	var rv []string
	for n, v := range auth.NamespaceActionGroup_value {
		if v != int32(auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED) {
			rv = append(rv, n)
		}
	}
	return rv
}

func toNamespaceActionGroup(permission string) (auth.NamespaceActionGroup, error) {
	p := strings.ToLower(strings.TrimSpace(permission))
	var ag auth.NamespaceActionGroup
	for n, v := range auth.NamespaceActionGroup_value {
		if strings.ToLower(n) == p {
			ag = auth.NamespaceActionGroup(v)
			break
		}
	}
	if ag == auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED {
		return auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED,
			fmt.Errorf("invalid permission: should be one of '%s'", strings.Join(getNamespaceActionGroups(), ","))
	}
	return ag, nil
}

func (c *RoleClient) getNamespaceRoleByPermission(namespace string, permission string) error {

	ag, err := toNamespaceActionGroup(permission)
	if err != nil {
		return err
	}
	res, err := c.client.GetRolesByPermissions(c.ctx, &authservice.GetRolesByPermissionsRequest{
		Specs: []*auth.RoleSpec{{
			NamespaceRoles: []*auth.NamespaceRoleSpec{{
				Namespace:   namespace,
				ActionGroup: ag,
			}},
		}},
	})
	if err != nil {
		return err
	}
	return PrintProto(res)
}

func NewRoleCommand(getRoleClientFn GetRoleClientFn) (CommandOut, error) {
	var c *RoleClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "Role",
			Aliases: []string{"ro"},
			Usage:   "Role operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getRoleClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:    "list",
					Usage:   "List roles in the account",
					Aliases: []string{"l"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    userIDFlagName,
							Usage:   "List roles that are currently assigned to the user",
							Aliases: []string{"i"},
						},
						&cli.StringFlag{
							Name:    NamespaceFlagName,
							Usage:   "List roles that give access to the namespace.",
							Aliases: []string{"n"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listRoles(ctx.String(userIDFlagName), ctx.String(NamespaceFlagName))
					},
				},
				{
					Name:    "get-account-role",
					Usage:   "Get an account role by permissions",
					Aliases: []string{"gar"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "permission",
							Usage:    fmt.Sprintf("The permission the role grants. one of: %s", getAccountActionGroups()),
							Aliases:  []string{"p"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.getAccountRoleByPermission(
							ctx.String("permission"),
						)
					},
				},
				{
					Name:    "get-namespace-role",
					Usage:   "Get a namespace role by permissions",
					Aliases: []string{"gnr"},
					Flags: []cli.Flag{
						NamespaceFlag,
						&cli.StringFlag{
							Name:     "permission",
							Usage:    fmt.Sprintf("The permission the role grants. one of: %s", getNamespaceActionGroups()),
							Aliases:  []string{"p"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.getNamespaceRoleByPermission(
							ctx.String(NamespaceFlagName),
							ctx.String("permission"),
						)
					},
				},
			},
		},
	}, nil
}
