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
	s.Error(s.RunCmd("service-account", "get"))
	s.Error(s.RunCmd("service-account", "get", "--service-account-id"))
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(nil, errors.New("get service-account error")).Times(1)
	s.Error(s.RunCmd("service-account", "get", "--service-account-id", "test-service-account-id"))
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{}, nil).Times(1)
	s.Error(s.RunCmd("service-account", "get", "--service-account-id", "test-service-account-id"))
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{
		ServiceAccount: &auth.ServiceAccount{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
			},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("service-account", "get", "--service-account-id", "test-service-account-id"))
}

func (s *ServiceAccountTestSuite) TestList() {
	s.mockAuthService.EXPECT().GetServiceAccounts(gomock.Any(), gomock.Any()).Return(nil, errors.New("get service accounts error")).Times(1)
	s.Error(s.RunCmd("service-account", "list"))
	s.mockAuthService.EXPECT().GetServiceAccounts(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountsResponse{
		ServiceAccount: []*auth.ServiceAccount{{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
			},
		}},
	}, nil).Times(1)
	s.NoError(s.RunCmd("service-account", "list"))
}

func (s *ServiceAccountTestSuite) TestCreateServiceAccount() {
	s.mockAuthService.EXPECT().CreateServiceAccount(gomock.Any(), gomock.Any()).Return(nil, errors.New("create service account error")).Times(1)
	s.EqualError(s.RunCmd("service-account", "create", "--description", "test description", "--name", "test name", "--account-role", "Read"), "unable to create service account: create service account error")
	s.mockAuthService.EXPECT().CreateServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.CreateServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("service-account", "create", "--description", "test description", "--name", "test name", "--account-role", "Read"))
	s.mockAuthService.EXPECT().CreateServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.CreateServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("service-account", "create", "--description", "test description", "--name", "test name", "--account-role", "Admin", "--namespace-permission", "test-namespace=Admin"))
	s.mockAuthService.EXPECT().CreateServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.CreateServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("service-account", "create", "--description", "test description", "--name", "test name", "--account-role", "Read", "--namespace-permission", "test-namespace=Read"))
}

func (s *ServiceAccountTestSuite) TestDeleteServiceAccount() {
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(nil, errors.New("get service account error")).Times(1)
	s.EqualError(s.RunCmd("service-account", "delete", "--service-account-id", "test-service-account-id"), "unable to get service account: get service account error")
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{
		ServiceAccount: &auth.ServiceAccount{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().DeleteServiceAccount(gomock.Any(), gomock.Any()).Return(nil, errors.New("delete service account error")).Times(1)
	s.EqualError(s.RunCmd("service-account", "delete", "--service-account-id", "test-service-account-id"), "unable to delete service account: delete service account error")
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{
		ServiceAccount: &auth.ServiceAccount{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().DeleteServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.DeleteServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("service-account", "delete", "--service-account-id", "test-service-account-id"))
}

func (s *ServiceAccountTestSuite) TestInvalidSetAccountRole() {
	s.ErrorContains(
		s.RunCmd("service-account", "set-account-role", "--service-account-id", "test-service-account-id", "--account-role", "wrong-role"),
		"invalid account role wrong-role; valid types are:",
	)
}

func (s *ServiceAccountTestSuite) TestSetAccountRole() {
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{
		ServiceAccount: &auth.ServiceAccount{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_READ,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{
						"test-namespace": {
							Permission: auth.NAMESPACE_ACTION_GROUP_READ,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateServiceAccount(gomock.Any(), gomock.All(&updateServiceAccountRequestMatcher{
		request: &authservice.UpdateServiceAccountRequest{
			ServiceAccountId: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_DEVELOPER,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{
						"test-namespace": {
							Permission: auth.NAMESPACE_ACTION_GROUP_READ,
						},
					},
				},
			},
		},
	})).Return(&authservice.UpdateServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("service-account", "set-account-role", "--service-account-id", "test-service-account-id", "--account-role", "Developer"))
}

func (s *ServiceAccountTestSuite) TestSetAccountRoleAdmin() {
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{
		ServiceAccount: &auth.ServiceAccount{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_READ,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{
						"test-namespace": {
							Permission: auth.NAMESPACE_ACTION_GROUP_READ,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateServiceAccount(gomock.Any(), gomock.All(&updateServiceAccountRequestMatcher{
		request: &authservice.UpdateServiceAccountRequest{
			ServiceAccountId: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_ADMIN,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{},
				},
			},
		},
	})).Return(&authservice.UpdateServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("service-account", "set-account-role", "--service-account-id", "test-service-account-id", "--account-role", "Admin"))
}

func (s *ServiceAccountTestSuite) TestInvalidSetNamespacePermissions() {
	s.ErrorContains(
		s.RunCmd("service-account", "set-namespace-permissions", "--service-account-id", "test-service-account-id", "-p", "test-namespace-1=wrong-role"),
		"invalid namespace permission \"wrong-role\" must be one of:",
	)
}

func (s *ServiceAccountTestSuite) TestSetNamespacePermissions() {
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{
		ServiceAccount: &auth.ServiceAccount{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_READ,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateServiceAccount(gomock.Any(), gomock.All(&updateServiceAccountRequestMatcher{
		request: &authservice.UpdateServiceAccountRequest{
			ServiceAccountId: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_READ,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{
						"test-namespace-1": {
							Permission: auth.NAMESPACE_ACTION_GROUP_READ,
						},
					},
				},
			},
		},
	})).Return(&authservice.UpdateServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("service-account", "set-namespace-permissions", "--service-account-id", "test-service-account-id", "-p", "test-namespace-1=Read"))
}

func (s *ServiceAccountTestSuite) TestSetNamespacePermissionsEmpty() {
	s.mockAuthService.EXPECT().GetServiceAccount(gomock.Any(), gomock.Any()).Return(&authservice.GetServiceAccountResponse{
		ServiceAccount: &auth.ServiceAccount{
			Id: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_READ,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{
						"test-namespace-1": {
							Permission: auth.NAMESPACE_ACTION_GROUP_READ,
						},
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateServiceAccount(gomock.Any(), gomock.All(&updateServiceAccountRequestMatcher{
		request: &authservice.UpdateServiceAccountRequest{
			ServiceAccountId: "test-service-account-id",
			Spec: &auth.ServiceAccountSpec{
				Name:        "test-service-account-name",
				Description: "test-service-account-desc",
				Access: &auth.Access{
					AccountAccess: &auth.AccountAccess{
						Role: auth.ACCOUNT_ACTION_GROUP_READ,
					},
					NamespaceAccesses: map[string]*auth.NamespaceAccess{},
				},
			},
		},
	})).Return(&authservice.UpdateServiceAccountResponse{
		RequestStatus: &request.RequestStatus{
			State: request.STATE_FULFILLED,
		},
	}, nil)
	s.NoError(s.RunCmd("service-account", "set-namespace-permissions", "--service-account-id", "test-service-account-id"))
}
