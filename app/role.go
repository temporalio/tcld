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

func getAccountRole(ctx context.Context, client authservice.AuthServiceClient, permission string) (*auth.Role, error) {
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
	if len(res.Roles) == 0 {
		return nil, fmt.Errorf("no roles found")
	}
	if len(res.Roles) > 1 {
		return nil, fmt.Errorf("more than 1 account role found: %s", res.Roles)
	}
	return res.Roles[0], nil
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
