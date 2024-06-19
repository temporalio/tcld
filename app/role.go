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

func getNamespaceRolesBatch(ctx context.Context, client authservice.AuthServiceClient, namespaceActionGroups map[string]string) ([]*auth.Role, error) {
	var roleSpecs []*auth.RoleSpec
	for namespace, actionGroup := range namespaceActionGroups {
		ag, err := toNamespaceActionGroup(actionGroup)
		if err != nil {
			return nil, err
		}
		roleSpecs = append(roleSpecs, &auth.RoleSpec{
			NamespaceRoles: []*auth.NamespaceRoleSpec{{
				Namespace:   namespace,
				ActionGroup: ag,
			}},
		})
	}
	res, err := client.GetRolesByPermissions(ctx, &authservice.GetRolesByPermissionsRequest{
		Specs: roleSpecs,
	})
	if err != nil {
		return nil, fmt.Errorf("unable get namespace roles: %v", err)
	}
	if len(res.Roles) == 0 {
		return nil, fmt.Errorf("no roles found")
	}
	return res.Roles, nil
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
		return nil, fmt.Errorf("unable to get account role: %v", err)
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
