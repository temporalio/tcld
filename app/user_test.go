package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	authservicemock "github.com/temporalio/tcld/protogen/apimock/authservice/v1"
	"github.com/urfave/cli/v2"
)

func TestUser(t *testing.T) {
	suite.Run(t, new(UserTestSuite))
}

type UserTestSuite struct {
	suite.Suite
	cliApp          *cli.App
	mockCtrl        *gomock.Controller
	mockAuthService *authservicemock.MockAuthServiceClient
}

func (s *UserTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockAuthService = authservicemock.NewMockAuthServiceClient(s.mockCtrl)
	out, err := NewUserCommand(func(ctx *cli.Context) (*UserClient, error) {
		return &UserClient{
			ctx:    context.TODO(),
			client: s.mockAuthService,
		}, nil
	})
	s.Require().NoError(err)

	cmds := []*cli.Command{
		out.Command,
	}
	flags := []cli.Flag{
		AutoConfirmFlag,
	}
	s.cliApp, _ = NewTestApp(s.T(), cmds, flags)
}

func (s *UserTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *UserTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

// updateUserRequestMatcher tests that update user request inputs match
type updateUserRequestMatcher struct {
	request *authservice.UpdateUserRequest
}

func (m *updateUserRequestMatcher) Matches(x interface{}) bool {
	u := x.(*authservice.UpdateUserRequest)
	return reflect.DeepEqual(m.request, u)
}

func (m *updateUserRequestMatcher) String() string {
	return ""
}

func (s *UserTestSuite) TestGet() {
	s.Error(s.RunCmd("user", "get"))
	s.Error(s.RunCmd("user", "get", "--user-email", "test@example.com", "--user-id", "test-user-id"))
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(nil, errors.New("get user error")).Times(1)
	s.Error(s.RunCmd("user", "get", "--user-email", "test@example.com"))
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{}, nil).Times(1)
	s.Error(s.RunCmd("user", "get", "--user-email", "test@example.com"))
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(2)
	s.mockAuthService.EXPECT().GetRoles(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-dev-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
				},
			},
			{
				Id:   "test-ns1-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{{
						Namespace:   "test-ns1",
						ActionGroup: auth.NAMESPACE_ACTION_GROUP_ADMIN,
					}},
				},
			},
		},
	}, nil).Times(2)
	s.NoError(s.RunCmd("user", "get", "--user-email", "test@example.com"))
	s.NoError(s.RunCmd("user", "get", "--user-id", "test-user-id"))
}

func (s *UserTestSuite) TestList() {
	s.mockAuthService.EXPECT().GetUsers(gomock.Any(), gomock.Any()).Return(nil, errors.New("get users error")).Times(1)
	s.Error(s.RunCmd("user", "list"))
	s.mockAuthService.EXPECT().GetUsers(gomock.Any(), gomock.Any()).Return(&authservice.GetUsersResponse{
		Users: []*auth.User{{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		}},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRoles(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-dev-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
				},
			},
			{
				Id:   "test-ns1-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{{
						Namespace:   "test-ns1",
						ActionGroup: auth.NAMESPACE_ACTION_GROUP_ADMIN,
					}},
				},
			},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user", "list"))
}

func (s *UserTestSuite) TestInviteErrors() {
	s.Error(s.RunCmd("user", "invite"))
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(nil, errors.New("get roles by permissions error"))
	s.Error(s.RunCmd("user", "invite", "--user-email", "test@example.com", "--account-role", "admin"))
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{{
			Id:   "account-admin-role",
			Type: auth.ROLE_TYPE_PREDEFINED,
		}},
	}, nil)
	s.mockAuthService.EXPECT().InviteUsers(gomock.Any(), gomock.Any()).Return(nil, errors.New("invite users error")).Times(1)
	s.Error(s.RunCmd("user", "invite", "--user-email", "test@example.com", "--account-role", "admin"))
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{{
			Id:   "account-dev-role",
			Type: auth.ROLE_TYPE_PREDEFINED,
		}},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{{
			Id:   "namespace-admin-role",
			Type: auth.ROLE_TYPE_PREDEFINED,
		}},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().InviteUsers(gomock.Any(), gomock.Any()).Return(nil, errors.New("error")).Times(1)
	s.Error(s.RunCmd("user", "invite", "--user-email", "test@example.com", "--account-role", "developer", "--namespace-permission", "ns1=Admin"))
}

func (s *UserTestSuite) TestParsingNamespacePermissions() {
	namespaceActionGroups, err := toNamespacePermissionsMap([]string{"ns1=Admin", "ns2=Write", "ns3=Read"})
	s.NoError(err)
	for namespace, actionGroup := range namespaceActionGroups {
		s.NotEmpty(namespace)
		_, err := toNamespaceActionGroup(actionGroup)
		s.NoError(err)
	}
}

func (s *UserTestSuite) TestParsingNamespacePermissionsErrors() {
	_, err := toNamespacePermissionsMap([]string{"=Admin"})
	s.EqualError(err, "namespace must not be empty in namespace permission")
	_, err = toNamespacePermissionsMap([]string{"ns1="})
	s.EqualError(err, "permission must not be empty in namespace permission")
	_, err = toNamespacePermissionsMap([]string{"=="})
	s.EqualError(err, "invalid namespace permission \"==\" must be of format: \"namespace=permission\"")
	_, err = toNamespacePermissionsMap([]string{"ns1=wrongpermission"})
	s.ErrorContains(err, "invalid namespace permission \"wrongpermission\" must be one of:")
	ag, err := toNamespacePermissionsMap([]string{"ns1=Admin"})
	s.NoError(err)
	s.Equal("Admin", ag["ns1"])
	_, err = toNamespaceActionGroup("wrongpermission")
	s.ErrorContains(err, "invalid action group: should be one of")
}

func (s *UserTestSuite) TestInviteSuccess() {
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{{
			Id:   "account-dev-role",
			Type: auth.ROLE_TYPE_PREDEFINED,
		}},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{{
			Id:   "namespace-admin-role",
			Type: auth.ROLE_TYPE_PREDEFINED,
		}},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().InviteUsers(gomock.Any(), gomock.Any()).Return(&authservice.InviteUsersResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user", "invite", "--user-email", "test@example.com", "--account-role", "developer", "--namespace-permission", "ns1=Admin"))
}

func (s *UserTestSuite) TestResendInvite() {
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(nil, errors.New("get user error")).Times(1)
	s.EqualError(s.RunCmd("user", "resend-invite", "--user-email", "test@example.com"), "unable to get user: get user error")
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().ResendUserInvite(gomock.Any(), gomock.Any()).Return(nil, errors.New("resend user invite error")).Times(1)
	s.EqualError(s.RunCmd("user", "resend-invite", "--user-email", "test@example.com"), "unable to resend invitation for user: resend user invite error")
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().ResendUserInvite(gomock.Any(), gomock.Any()).Return(&authservice.ResendUserInviteResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user", "resend-invite", "--user-email", "test@example.com"))
}

func (s *UserTestSuite) TestDeleteUser() {
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(nil, errors.New("get user error")).Times(1)
	s.EqualError(s.RunCmd("user", "delete", "--user-email", "test@example.com"), "unable to get user: get user error")
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().DeleteUser(gomock.Any(), gomock.Any()).Return(nil, errors.New("delete user error")).Times(1)
	s.EqualError(s.RunCmd("user", "delete", "--user-email", "test@example.com"), "unable to delete user: delete user error")
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().DeleteUser(gomock.Any(), gomock.Any()).Return(&authservice.DeleteUserResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user", "delete", "--user-email", "test@example.com"))
}

func (s *UserTestSuite) TestSetAccountRole() {
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRoles(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_ADMIN,
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-developer-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateUser(gomock.Any(), gomock.All(&updateUserRequestMatcher{
		request: &authservice.UpdateUserRequest{
			UserId: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
				Roles: []string{
					"test-account-developer-role",
				},
			},
		},
	})).Return(&authservice.UpdateUserResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("user", "set-account-role", "--user-email", "test@example.com", "--account-role", "Developer"))
}

func (s *UserTestSuite) TestSetAccountRoleAdmin() {
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRoles(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-developer-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
				},
			},
			{
				Id:   "test-namespace-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{
						{
							Namespace:   "ns1",
							ActionGroup: auth.NAMESPACE_ACTION_GROUP_ADMIN,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_ADMIN,
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateUser(gomock.Any(), gomock.All(&updateUserRequestMatcher{
		request: &authservice.UpdateUserRequest{
			UserId: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
				Roles: []string{
					"test-account-admin-role",
				},
			},
		},
	})).Return(&authservice.UpdateUserResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("user", "set-account-role", "--user-email", "test@example.com", "--account-role", "Admin"))
}

func (s *UserTestSuite) TestSetAccountRoleNone() {
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRoles(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-developer-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
				},
			},
			{
				Id:   "test-namespace-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{
						{
							Namespace:   "ns1",
							ActionGroup: auth.NAMESPACE_ACTION_GROUP_ADMIN,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateUser(gomock.Any(), gomock.All(&updateUserRequestMatcher{
		request: &authservice.UpdateUserRequest{
			UserId: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
				Roles: []string{"test-namespace-admin-role"},
			},
		},
	})).Return(&authservice.UpdateUserResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("user", "set-account-role", "--user-email", "test@example.com", "--account-role", "none"))
}

func (s *UserTestSuite) TestSetNamespacePermissions() {
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRoles(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-developer-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
				},
			},
			{
				Id:   "test-ns0-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{
						{
							Namespace:   "ns0",
							ActionGroup: auth.NAMESPACE_ACTION_GROUP_ADMIN,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRolesByPermissions(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesByPermissionsResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-ns1-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{
						{
							Namespace:   "ns1",
							ActionGroup: auth.NAMESPACE_ACTION_GROUP_ADMIN,
						},
					},
				},
			},
			{
				Id:   "test-ns2-write-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{
						{
							Namespace:   "ns2",
							ActionGroup: auth.NAMESPACE_ACTION_GROUP_WRITE,
						},
					},
				},
			},
			{
				Id:   "test-ns3-read-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{
						{
							Namespace:   "ns3",
							ActionGroup: auth.NAMESPACE_ACTION_GROUP_READ,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateUser(gomock.Any(), gomock.All(&updateUserRequestMatcher{
		request: &authservice.UpdateUserRequest{
			UserId: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
				Roles: []string{
					"test-account-developer-role",
					"test-ns1-admin-role",
					"test-ns2-write-role",
					"test-ns3-read-role",
				},
			},
		},
	})).Return(&authservice.UpdateUserResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("user", "set-namespace-permissions", "--user-email", "test@example.com", "-p", "ns1=Admin", "-p", "ns2=Write", "-p", "ns3=Read"))
}

func (s *UserTestSuite) TestSetNamespacePermissionsEmpty() {
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetRoles(gomock.Any(), gomock.Any()).Return(&authservice.GetRolesResponse{
		Roles: []*auth.Role{
			{
				Id:   "test-account-developer-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					AccountRole: &auth.AccountRoleSpec{
						ActionGroup: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
				},
			},
			{
				Id:   "test-ns0-admin-role",
				Type: auth.ROLE_TYPE_PREDEFINED,
				Spec: &auth.RoleSpec{
					NamespaceRoles: []*auth.NamespaceRoleSpec{
						{
							Namespace:   "ns0",
							ActionGroup: auth.NAMESPACE_ACTION_GROUP_ADMIN,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateUser(gomock.Any(), gomock.All(&updateUserRequestMatcher{
		request: &authservice.UpdateUserRequest{
			UserId: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
				Roles: []string{
					"test-account-developer-role",
				},
			},
		},
	})).Return(&authservice.UpdateUserResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("user", "set-namespace-permissions", "--user-email", "test@example.com"))
}
