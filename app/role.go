package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
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

func getNamespaceRolesFromMap(ctx context.Context, client authservice.AuthServiceClient, namespaceActionGroups map[string]string) ([]*auth.Role, error) {
	var res []*auth.Role
	for namespace, actionGroup := range namespaceActionGroups {
		r, err := getNamespaceRole(ctx, client, namespace, actionGroup)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func getNamespaceRole(ctx context.Context, client authservice.AuthServiceClient, namespace string, actionGroup string) (*auth.Role, error) {
	ag, err := toNamespaceActionGroup(actionGroup)
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
	if len(res.Roles) == 0 {
		return nil, fmt.Errorf("no roles found")
	}
	if len(res.Roles) > 1 {
		return nil, fmt.Errorf("more than 1 account role found: %s", res.Roles)
	}
	return res.Roles[0], nil
}

func getAccountRole(ctx context.Context, client authservice.AuthServiceClient, actionGroup string) (*auth.Role, error) {
	ag, err := toAccountActionGroup(actionGroup)
	if err != nil {
		return nil, err
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
	if len(res.Roles) == 0 {
		return nil, fmt.Errorf("no roles found")
	}
	if len(res.Roles) > 1 {
		return nil, fmt.Errorf("more than 1 account role found: %s", res.Roles)
	}
	return res.Roles[0], nil
}

func toAccountActionGroup(actionGroup string) (auth.AccountActionGroup, error) {
	g := strings.ToLower(strings.TrimSpace(actionGroup))
	var ag auth.AccountActionGroup
	for n, v := range auth.AccountActionGroup_value {
		if strings.ToLower(n) == g {
			ag = auth.AccountActionGroup(v)
			break
		}
	}
	if ag == auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED {
		return auth.ACCOUNT_ACTION_GROUP_UNSPECIFIED,
			fmt.Errorf("invalid action group: should be one of: %s", accountActionGroups)
	}
	return ag, nil
}

func toNamespaceActionGroup(actionGroup string) (auth.NamespaceActionGroup, error) {
	g := strings.ToLower(strings.TrimSpace(actionGroup))
	var ag auth.NamespaceActionGroup
	for n, v := range auth.NamespaceActionGroup_value {
		if strings.ToLower(n) == g {
			ag = auth.NamespaceActionGroup(v)
			break
		}
	}
	if ag == auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED {
		return auth.NAMESPACE_ACTION_GROUP_UNSPECIFIED,
			fmt.Errorf("invalid action group: should be one of: %s", namespaceActionGroups)
	}
	return ag, nil
}
