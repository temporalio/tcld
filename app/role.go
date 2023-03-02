package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
)

var (
	accountActionGroups   = getAccountActionGroups()
	namespaceActionGroups = getNamespaceActionGroups()
)

func getAccountActionGroups() []string {
	var rv []string
	for n, v := range auth.AccountActionGroup_value {
		if v != int32(auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED) {
			rv = append(rv, n)
		}
	}
	return rv
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
			fmt.Errorf("invalid permission: should be one of: %s", accountActionGroups)
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
			fmt.Errorf("invalid permission: should be one of: %s", namespaceActionGroups)
	}
	return ag, nil
}

func getNamespaceRolesForPermission(ctx context.Context, client authservice.AuthServiceClient, namespace string, permission string) (*authservice.GetRolesByPermissionsResponse, error) {

	ag, err := toNamespaceActionGroup(permission)
	if err != nil {
		return nil, err
	}
	res, err := client.GetRolesByPermissions(ctx, &authservice.GetRolesByPermissionsRequest{
		Specs: []*auth.RoleSpec{{
			NamespaceRoles: []*auth.NamespaceRoleSpec{{
				Namespace:   namespace,
				ActionGroup: ag,
			}},
		}},
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func getNamespaceRoles(ctx context.Context, client authservice.AuthServiceClient, namespace string) (*authservice.GetRolesByPermissionsResponse, error) {

	specs := []*auth.RoleSpec{}
	for i := range auth.NamespaceActionGroup_name {
		if i != int32(auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED) {
			specs = append(specs, &auth.RoleSpec{
				NamespaceRoles: []*auth.NamespaceRoleSpec{{
					Namespace:   namespace,
					ActionGroup: auth.NamespaceActionGroup(i),
				}},
			})
		}
	}
	res, err := client.GetRolesByPermissions(ctx, &authservice.GetRolesByPermissionsRequest{Specs: specs})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func computeRole(
	ctx context.Context,
	client authservice.AuthServiceClient,
	accountAccess string,
	namespaceAccess string,
	namespace string,
) (*auth.Role, error) {

	var roles []*auth.Role
	if accountAccess == "" && namespaceAccess == "" {
		return nil, fmt.Errorf("both account-access and namespace-access are not set")
	}
	if accountAccess != "" {
		if namespace != "" || namespaceAccess != "" {
			return nil, fmt.Errorf("both account-access and namespace-access are set")
		}
		res, err := getAccountRoles(ctx, client, accountAccess)
		if err != nil {
			return nil, err
		}
		roles = res.Roles
	} else {
		if namespace == "" {
			return nil, fmt.Errorf("namespace not provided")

		}
		res, err := getNamespaceRolesForPermission(ctx, client, namespace, namespaceAccess)
		if err != nil {
			return nil, err
		}
		roles = res.Roles
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("no roles found")
	}
	if len(roles) > 0 {
		return nil, fmt.Errorf("more then one role found: %s", roles)
	}
	return roles[0], nil
}

func (c *RoleClient) listRoles(accountAccess string, namespace string, namespaceAccess string) error {
	totalRes := []proto.Message{}

	if accountAccess == "" && namespace == "" && namespaceAccess == "" {
		pageToken := ""
		for {
			res, err := c.client.GetRoles(c.ctx, &authservice.GetRolesRequest{
				PageToken: pageToken,
				Namespace: namespace,
			})
			if err != nil {
				return err
			}
			for i := range res.Roles {
				totalRes = append(totalRes, res.Roles[i])
			}
			// Check if we should continue paging
			pageToken = res.NextPageToken
			if len(pageToken) == 0 {
				break
			}
		}
	} else {
		if accountAccess != "" {
			res, err := getAccountRoles(c.ctx, c.client, accountAccess)
			if err != nil {
				return err
			}
			for i := range res.Roles {
				totalRes = append(totalRes, res.Roles[i])
			}
		}
		if namespace != "" {
			if namespaceAccess == "" {
				res, err := getNamespaceRoles(c.ctx, c.client, namespace)
				if err != nil {
					return err
				}
				for i := range res.Roles {
					totalRes = append(totalRes, res.Roles[i])
				}
			} else {
				res, err := getNamespaceRolesForPermission(c.ctx, c.client, namespace, namespaceAccess)
				if err != nil {
					return err
				}
				for i := range res.Roles {
					totalRes = append(totalRes, res.Roles[i])
				}
			}
		}
	}
	return PrintProtoSlice("Roles", totalRes)
}

func NewRoleCommand(getRoleClientFn GetRoleClientFn) (CommandOut, error) {
	var c *RoleClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "role",
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
							Name:    "account-access",
							Usage:   fmt.Sprintf("List roles that give global %s access.", accountActionGroups),
							Aliases: []string{"aa"},
						},
						&cli.StringFlag{
							Name:    NamespaceFlagName,
							Usage:   "List roles that give access to namespace.",
							Aliases: []string{"n"},
						},
						&cli.StringFlag{
							Name:    "namespace-access",
							Usage:   fmt.Sprintf("List roles that give %s access to the namespace", namespaceActionGroups),
							Aliases: []string{"na"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listRoles(
							ctx.String("account-access"),
							ctx.String(NamespaceFlagName),
							ctx.String("namespace-access"),
						)
					},
				},
			},
		},
	}, nil
}
