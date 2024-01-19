package app

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	authservicemock "github.com/temporalio/tcld/protogen/apimock/authservice/v1"
	"github.com/urfave/cli/v2"
	"reflect"
	"testing"
)

func TestServiceAccount(t *testing.T) {
	suite.Run(t, new(ServiceAccountTestSuite))
}

type ServiceAccountTestSuite struct {
	suite.Suite
	cliApp          *cli.App
	mockCtrl        *gomock.Controller
	mockAuthService *authservicemock.MockAuthServiceClient
}

func (s *ServiceAccountTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockAuthService = authservicemock.NewMockAuthServiceClient(s.mockCtrl)
	out, err := NewServiceAccountCommand(func(ctx *cli.Context) (*ServiceAccountClient, error) {
		return &ServiceAccountClient{
			ctx:    context.TODO(),
			client: s.mockAuthService,
		}, nil
	})
	s.Require().NoError(err)
	AutoConfirmFlag.Value = true
	s.cliApp = &cli.App{
		Name:     "test",
		Commands: []*cli.Command{out.Command},
		Flags: []cli.Flag{
			AutoConfirmFlag,
		},
	}
}

func (s *ServiceAccountTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *ServiceAccountTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

// updateServiceAccountRequestMatcher tests that update service account request inputs match
type updateServiceAccountRequestMatcher struct {
	request *authservice.UpdateServiceAccountRequest
}

func (m *updateServiceAccountRequestMatcher) Matches(x interface{}) bool {
	u := x.(*authservice.UpdateServiceAccountRequest)
	return reflect.DeepEqual(m.request, u)
}

func (m *updateServiceAccountRequestMatcher) String() string {
	return ""
}

func (s *ServiceAccountTestSuite) TestGet() {
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

func (s *ServiceAccountTestSuite) TestList() {
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

func (s *ServiceAccountTestSuite) TestDeleteUser() {
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

func (s *ServiceAccountTestSuite) TestSetAccountRole() {
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

func (s *ServiceAccountTestSuite) TestSetAccountRoleAdmin() {
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

func (s *ServiceAccountTestSuite) TestSetNamespacePermissions() {
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

func (s *ServiceAccountTestSuite) TestSetNamespacePermissionsEmpty() {
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
