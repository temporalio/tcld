package app

import (
	"context"
	"fmt"
	"github.com/temporalio/tcld/protogen/temporal/api/cloud/identity/v1"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/urfave/cli/v2"
)

const (
	serviceAccountIDFlagName          = "service-account-id"
	serviceAccountNameFlagName        = "name"
	serviceAccountDescriptionFlagName = "description"
)

var (
	serviceAccountIDFlag = &cli.StringFlag{
		Name:     serviceAccountIDFlagName,
		Usage:    "The service account id",
		Required: true,
		Aliases:  []string{"id"},
	}
	serviceAccountDescriptionFlag = &cli.StringFlag{
		Name:    serviceAccountDescriptionFlagName,
		Usage:   "The service account description",
		Aliases: []string{"d"},
	}
	serviceAccountNameFlag = &cli.StringFlag{
		Name:    serviceAccountNameFlagName,
		Usage:   "The service account name",
		Aliases: []string{"n"},
	}
)

type (
	ServiceAccountClient struct {
		client authservice.AuthServiceClient
		ctx    context.Context
	}
	GetServiceAccountClientFn func(ctx *cli.Context) (*ServiceAccountClient, error)
)

func GetServiceAccountClient(ctx *cli.Context) (*ServiceAccountClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &ServiceAccountClient{
		client: authservice.NewAuthServiceClient(conn),
		ctx:    ct,
	}, nil
}

func (c *ServiceAccountClient) listServiceAccounts(
	pageToken string,
	pageSize int,
) error {
	res, err := c.client.GetServiceAccounts(c.ctx, &authservice.GetServiceAccountsRequest{
		PageToken: pageToken,
		PageSize:  int32(pageSize),
	})
	if err != nil {
		return fmt.Errorf("unable to get service accounts: %v", err)
	}
	return PrintProto(res)
}

func (c *ServiceAccountClient) getServiceAccount(serviceAccountID string) (*auth.ServiceAccount, error) {
	res, err := c.client.GetServiceAccount(c.ctx, &authservice.GetServiceAccountRequest{
		ServiceAccountId: serviceAccountID,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to get service account: %v", err)
	}
	if res.ServiceAccount == nil || res.ServiceAccount.Id == "" {
		// this should never happen, the server should return an error when the service account is not found
		return nil, fmt.Errorf("invalid service account returned by server")
	}
	return res.ServiceAccount, nil
}

func (c *ServiceAccountClient) deleteServiceAccount(
	ctx *cli.Context,
	serviceAccountID string,
) error {
	sa, err := c.getServiceAccount(serviceAccountID)
	if err != nil {
		return err
	}
	req := &authservice.DeleteServiceAccountRequest{
		ServiceAccountId: sa.Id,
		ResourceVersion:  ctx.String(ResourceVersionFlagName),
		AsyncOperationId: ctx.String(RequestIDFlagName),
	}
	if req.ResourceVersion == "" {
		req.ResourceVersion = sa.ResourceVersion
	}
	resp, err := c.client.DeleteServiceAccount(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to delete service account: %w", err)
	}
	return PrintProto(resp.AsyncOperation)
}

func (c *ServiceAccountClient) performUpdate(
	ctx *cli.Context,
	serviceAccountID string,
	name string,
	description string,
	disabled *bool,
	accountRole string,
	namespaceRoles map[string]string,
) error {
	sa, err := c.getServiceAccount(serviceAccountID)
	if err != nil {
		return err
	}
	spec := sa.Spec

	if len(name) > 0 {
		spec.Name = name
	}
	if len(description) > 0 {
		spec.Description = description
	}
	if disabled != nil {
		spec.Disabled = *disabled
	}
	if len(accountRole) > 0 {
		spec.Access.AccountAccess = &identity.AccountAccess{
			Role: accountRole,
		}
	}
	if namespaceRoles != nil {
		nrs := map[string]*identity.NamespaceAccess{}
		for ns, p := range namespaceRoles {
			nrs[ns] = &identity.NamespaceAccess{
				Permission: p,
			}
		}
		spec.Access.NamespaceAccesses = nrs
	}

	req := &authservice.UpdateServiceAccountRequest{
		ServiceAccountId: serviceAccountID,
		Spec:             spec,
	}
	if ctx.IsSet(ResourceVersionFlagName) {
		req.ResourceVersion = ctx.String(ResourceVersionFlagName)
	}
	if ctx.IsSet(RequestIDFlagName) {
		req.AsyncOperationId = ctx.String(RequestIDFlagName)
	}
	if req.ResourceVersion == "" {
		req.ResourceVersion = sa.ResourceVersion
	}

	resp, err := c.client.UpdateServiceAccount(c.ctx, req)
	if err != nil {
		return fmt.Errorf("unable to update service account: %w", err)
	}
	return PrintProto(resp.AsyncOperation)
}

func NewServiceAccountCommand(getServiceAccountClientFn GetServiceAccountClientFn) (CommandOut, error) {
	var c *ServiceAccountClient
	return CommandOut{
		Command: &cli.Command{
			Name:    "service-account",
			Aliases: []string{"sa"},
			Usage:   "Service Account management operations",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getServiceAccountClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:    "list",
					Usage:   "List service accounts",
					Aliases: []string{"l"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    pageTokenFlagName,
							Usage:   "Page token for paging list service accounts request",
							Aliases: []string{"p"},
						},
						&cli.IntFlag{
							Name:    pageSizeFlagName,
							Usage:   "Page size for paging list service accounts request",
							Value:   10,
							Aliases: []string{"s"},
						},
					},
					Action: func(ctx *cli.Context) error {
						return c.listServiceAccounts(ctx.String(pageTokenFlagName), ctx.Int(pageSizeFlagName))
					},
				},
				{
					Name:    "get",
					Usage:   "Get service account information",
					Aliases: []string{"g"},
					Flags: []cli.Flag{
						serviceAccountIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						sa, err := c.getServiceAccount(ctx.String(serviceAccountIDFlagName))
						if err != nil {
							return err
						}
						return PrintProto(sa)
					},
				},
				{
					Name:    "update",
					Usage:   "Update service account from Temporal Cloud",
					Aliases: []string{"u"},
					Flags: []cli.Flag{
						serviceAccountIDFlag,
						serviceAccountDescriptionFlag,
						serviceAccountNameFlag,
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						if len(ctx.String(serviceAccountDescriptionFlagName)) == 0 &&
							len(ctx.String(serviceAccountNameFlagName)) == 0 {
							return fmt.Errorf("no update parameters provided")
						}
						return c.performUpdate(
							ctx,
							ctx.String(serviceAccountIDFlagName),
							ctx.String(serviceAccountNameFlagName),
							ctx.String(serviceAccountDescriptionFlagName),
							nil,
							"",
							nil,
						)
					},
				},
				{
					Name:  "disable",
					Usage: "Disable service account from Temporal Cloud",
					Flags: []cli.Flag{
						serviceAccountIDFlag,
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						disabled := true
						return c.performUpdate(
							ctx,
							ctx.String(serviceAccountIDFlagName),
							"",
							"",
							&disabled,
							"",
							nil,
						)
					},
				},
				{
					Name:  "enable",
					Usage: "Enable service account from Temporal Cloud",
					Flags: []cli.Flag{
						serviceAccountIDFlag,
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						disabled := false
						return c.performUpdate(
							ctx,
							ctx.String(serviceAccountIDFlagName),
							"",
							"",
							&disabled,
							"",
							nil,
						)
					},
				},
				{
					Name:    "delete",
					Usage:   "Delete service account from Temporal Cloud",
					Aliases: []string{"d"},
					Flags: []cli.Flag{
						serviceAccountIDFlag,
						ResourceVersionFlag,
						RequestIDFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.deleteServiceAccount(
							ctx,
							ctx.String(serviceAccountIDFlagName),
						)
					},
				},
				{
					Name:    "set-account-role",
					Usage:   "Set account role for a service account",
					Aliases: []string{"sar"},
					Flags: []cli.Flag{
						serviceAccountIDFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.StringFlag{
							Name:     accountRoleFlagName,
							Usage:    fmt.Sprintf("The account role to set on the service account; valid types are: %v", accountActionGroups),
							Required: true,
							Aliases:  []string{"ar"},
						},
					},
					Action: func(ctx *cli.Context) error {
						// validate input role
						if _, ok := auth.AccountActionGroup_value[ctx.String(accountRoleFlagName)]; !ok {
							return fmt.Errorf("invalid account role %v; valid types are: %v", ctx.String(accountRoleFlagName), accountActionGroups)
						}
						// if account role is admin unset the namespace permissions
						var namespacePermissions map[string]string
						if ctx.String(accountRoleFlagName) == auth.AccountActionGroup_name[int32(auth.ACCOUNT_ACTION_GROUP_ADMIN)] {
							y, err := ConfirmPrompt(ctx, "Setting admin role on service account. All existing namespace permissions will be replaced, please confirm")
							if err != nil {
								return err
							}
							if !y {
								fmt.Println("operation canceled")
								return nil
							}
							namespacePermissions = map[string]string{}
						}
						return c.performUpdate(
							ctx,
							ctx.String(serviceAccountIDFlagName),
							"",
							"",
							nil,
							ctx.String(accountRoleFlagName),
							namespacePermissions,
						)
					},
				},
				{
					Name:    "set-namespace-permissions",
					Usage:   "Set entirely new set of namespace permissions for a service account",
					Aliases: []string{"snp"},
					Flags: []cli.Flag{
						serviceAccountIDFlag,
						RequestIDFlag,
						ResourceVersionFlag,
						&cli.StringSliceFlag{
							Name:    namespacePermissionFlagName,
							Usage:   fmt.Sprintf("Flag can be used multiple times; value must be \"namespace=permission\"; valid types are: %v", namespaceActionGroups),
							Aliases: []string{"p"},
						},
					},
					Action: func(ctx *cli.Context) error {
						namespacePermissionsList := ctx.StringSlice(namespacePermissionFlagName)
						if len(namespacePermissionsList) == 0 {
							y, err := ConfirmPrompt(ctx, "Looks like you are about to remove all namespace permissions, please confirm")
							if err != nil {
								return err
							}
							if !y {
								fmt.Println("operation canceled")
								return nil
							}
						}
						fmt.Println(namespacePermissionsList)
						m, err := toNamespacePermissionsMap(namespacePermissionsList)
						fmt.Println(m)
						if err != nil {
							return err
						}
						return c.performUpdate(
							ctx,
							ctx.String(serviceAccountIDFlagName),
							"",
							"",
							nil,
							"",
							m,
						)
					},
				},
			},
		},
	}, nil
}
