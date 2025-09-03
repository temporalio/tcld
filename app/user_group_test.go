package app

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/identity/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/operation/v1"
	authservicemock "github.com/temporalio/tcld/protogen/apimock/authservice/v1"
	cloudservicemock "github.com/temporalio/tcld/protogen/apimock/cloudservice/v1"
	"github.com/urfave/cli/v2"
)

func TestUserGroup(t *testing.T) {
	suite.Run(t, new(UserGroupTestSuite))
}

type UserGroupTestSuite struct {
	suite.Suite
	cliApp           *cli.App
	mockCtrl         *gomock.Controller
	mockCloudService *cloudservicemock.MockCloudServiceClient
	mockAuthService  *authservicemock.MockAuthServiceClient
}

func (s *UserGroupTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockCloudService = cloudservicemock.NewMockCloudServiceClient(s.mockCtrl)
	s.mockAuthService = authservicemock.NewMockAuthServiceClient(s.mockCtrl)

	out, err := NewUserGroupCommand(func(ctx *cli.Context) (*UserGroupClient, error) {
		return &UserGroupClient{
			ctx:        context.TODO(),
			client:     s.mockCloudService,
			authClient: s.mockAuthService,
		}, nil
	})
	s.Require().NoError(err)

	cmds := []*cli.Command{
		out.Command,
	}
	flags := []cli.Flag{
		AutoConfirmFlag,
		IdempotentFlag,
	}
	s.cliApp, _ = NewTestApp(s.T(), cmds, flags)
}

func (s *UserGroupTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *UserGroupTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *UserGroupTestSuite) TestListGroups() {
	// Test successful list
	s.mockCloudService.EXPECT().GetUserGroups(gomock.Any(), &cloudservice.GetUserGroupsRequest{
		PageToken: "",
		PageSize:  10,
	}).Return(&cloudservice.GetUserGroupsResponse{
		Groups: []*identity.UserGroup{
			{
				Id: "group1",
				Spec: &identity.UserGroupSpec{
					DisplayName: "Test Group",
				},
			},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "list"))

	// Test with page token
	s.mockCloudService.EXPECT().GetUserGroups(gomock.Any(), &cloudservice.GetUserGroupsRequest{
		PageToken: "token1",
		PageSize:  20,
	}).Return(&cloudservice.GetUserGroupsResponse{}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "list", "--page-token", "token1", "--page-size", "20"))
}

func (s *UserGroupTestSuite) TestGetGroup() {
	// Test without required flags
	s.Error(s.RunCmd("user-group", "get"))

	// Test successful get
	s.mockCloudService.EXPECT().GetUserGroup(gomock.Any(), &cloudservice.GetUserGroupRequest{
		GroupId: "group1",
	}).Return(&cloudservice.GetUserGroupResponse{
		Group: &identity.UserGroup{
			Id: "group1",
			Spec: &identity.UserGroupSpec{
				DisplayName: "Test Group",
			},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "get", "--group-id", "group1"))

	// Test error case
	s.mockCloudService.EXPECT().GetUserGroup(gomock.Any(), &cloudservice.GetUserGroupRequest{
		GroupId: "group1",
	}).Return(nil, errors.New("some error")).Times(1)
	s.Error(s.RunCmd("user-group", "get", "--group-id", "group1"))
}

func (s *UserGroupTestSuite) TestCreateGroup() {
	// Test without required flags
	s.Error(s.RunCmd("user-group", "create"))

	// Test successful create
	s.mockCloudService.EXPECT().CreateUserGroup(gomock.Any(), &cloudservice.CreateUserGroupRequest{
		Spec: &identity.UserGroupSpec{
			DisplayName: "Test Group",
			Access: &identity.Access{
				AccountAccess: &identity.AccountAccess{
					Role: identity.ROLE_ADMIN,
				},
				NamespaceAccesses: map[string]*identity.NamespaceAccess{},
			},
			GroupType: &identity.UserGroupSpec_CloudGroup{
				CloudGroup: &identity.CloudGroupSpec{},
			},
		},
	}).Return(&cloudservice.CreateUserGroupResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: "op1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "create", "--display-name", "Test Group", "--account-role", "admin"))

	// Test successful create with namespace roles
	s.mockCloudService.EXPECT().CreateUserGroup(gomock.Any(), &cloudservice.CreateUserGroupRequest{
		Spec: &identity.UserGroupSpec{
			DisplayName: "Test Group with NS",
			Access: &identity.Access{
				AccountAccess: &identity.AccountAccess{
					Role: identity.ROLE_DEVELOPER,
				},
				NamespaceAccesses: map[string]*identity.NamespaceAccess{
					"test-namespace": {
						Permission: identity.PERMISSION_ADMIN,
					},
					"another-namespace": {
						Permission: identity.PERMISSION_READ,
					},
				},
			},
			GroupType: &identity.UserGroupSpec_CloudGroup{
				CloudGroup: &identity.CloudGroupSpec{},
			},
		},
	}).Return(&cloudservice.CreateUserGroupResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: "op1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "create", "--display-name", "Test Group with NS", "--account-role", "developer", "--namespace-role", "test-namespace-admin", "--namespace-role", "another-namespace-read"))

	// Test invalid namespace role
	err := s.RunCmd("user-group", "create", "--display-name", "Test Group", "--account-role", "admin", "--namespace-role", "invalid-role")
	s.Error(err)
	s.Contains(err.Error(), "Invalid namespace role: invalid-role")

	// Test invalid account role
	err = s.RunCmd("user-group", "create", "--display-name", "Test Group", "--account-role", "invalid")
	s.Error(err)
	s.Contains(err.Error(), "Invalid account role: invalid")
}

func (s *UserGroupTestSuite) TestSetAccess() {
	// Test without required flags
	s.Error(s.RunCmd("user-group", "set-access"))

	// Test successful set access
	s.mockCloudService.EXPECT().GetUserGroup(gomock.Any(), &cloudservice.GetUserGroupRequest{
		GroupId: "group1",
	}).Return(&cloudservice.GetUserGroupResponse{
		Group: &identity.UserGroup{
			Id: "group1",
			Spec: &identity.UserGroupSpec{
				DisplayName: "Test Group",
				Access: &identity.Access{
					AccountAccess: &identity.AccountAccess{
						Role: identity.ROLE_DEVELOPER,
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateUserGroup(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateUserGroupResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: "op1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "set-access", "--group-id", "group1", "--account-role", "admin"))

	// Test with namespace roles
	s.mockCloudService.EXPECT().GetUserGroup(gomock.Any(), &cloudservice.GetUserGroupRequest{
		GroupId: "group1",
	}).Return(&cloudservice.GetUserGroupResponse{
		Group: &identity.UserGroup{
			Id: "group1",
			Spec: &identity.UserGroupSpec{
				DisplayName: "Test Group",
				Access: &identity.Access{
					AccountAccess: &identity.AccountAccess{
						Role: identity.ROLE_ADMIN,
					},
				},
			},
		},
	}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateUserGroup(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateUserGroupResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: "op1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "set-access", "--group-id", "group1", "--account-role", "admin", "--namespace-role", "ns1-admin"))
}

func (s *UserGroupTestSuite) TestAddUsers() {
	// Test without required flags
	s.Error(s.RunCmd("user-group", "add-users"))

	// Test successful add users
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), &authservice.GetUserRequest{
		UserEmail: "user1@example.com",
	}).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "user1",
		},
	}, nil).Times(1)
	s.mockCloudService.EXPECT().AddUserGroupMember(gomock.Any(), gomock.Any()).Return(&cloudservice.AddUserGroupMemberResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: "op1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "add-users", "--group-id", "group1", "--user-email", "user1@example.com"))
}

func (s *UserGroupTestSuite) TestRemoveUsers() {
	// Test without required flags
	s.Error(s.RunCmd("user-group", "remove-users"))

	// Test successful remove users
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), &authservice.GetUserRequest{
		UserEmail: "user1@example.com",
	}).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "user1",
		},
	}, nil).Times(1)
	s.mockCloudService.EXPECT().RemoveUserGroupMember(gomock.Any(), gomock.Any()).Return(&cloudservice.RemoveUserGroupMemberResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: "op1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "remove-users", "--group-id", "group1", "--user-email", "user1@example.com"))
}

func (s *UserGroupTestSuite) TestListMembers() {
	// Test without required flags
	s.Error(s.RunCmd("user-group", "list-members"))

	// Test successful list members
	s.mockCloudService.EXPECT().GetUserGroupMembers(gomock.Any(), &cloudservice.GetUserGroupMembersRequest{
		GroupId:   "group1",
		PageToken: "",
		PageSize:  100,
	}).Return(&cloudservice.GetUserGroupMembersResponse{
		Members: []*identity.UserGroupMember{
			{
				MemberId: &identity.UserGroupMemberId{
					MemberType: &identity.UserGroupMemberId_UserId{
						UserId: "member1",
					},
				},
			},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "list-members", "--group-id", "group1"))

	// Test that the command works without page parameters (since it now auto-pages)
	// The function will make one call with page size 100 and empty page token
	s.mockCloudService.EXPECT().GetUserGroupMembers(gomock.Any(), &cloudservice.GetUserGroupMembersRequest{
		GroupId:   "group1",
		PageToken: "",
		PageSize:  100,
	}).Return(&cloudservice.GetUserGroupMembersResponse{
		Members: []*identity.UserGroupMember{
			{
				MemberId: &identity.UserGroupMemberId{
					MemberType: &identity.UserGroupMemberId_UserId{
						UserId: "member1",
					},
				},
				CreatedTime: nil,
			},
		},
		NextPageToken: "", // No more pages
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "list-members", "--group-id", "group1"))
}

func (s *UserGroupTestSuite) TestDeleteGroup() {
	// Test without required flags
	s.Error(s.RunCmd("user-group", "delete"))

	// Test successful delete
	s.mockCloudService.EXPECT().GetUserGroup(gomock.Any(), &cloudservice.GetUserGroupRequest{
		GroupId: "group1",
	}).Return(&cloudservice.GetUserGroupResponse{
		Group: &identity.UserGroup{
			Id: "group1",
			Spec: &identity.UserGroupSpec{
				DisplayName: "Test Group",
			},
		},
	}, nil).Times(1)
	s.mockCloudService.EXPECT().DeleteUserGroup(gomock.Any(), gomock.Any()).Return(&cloudservice.DeleteUserGroupResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: "op1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("user-group", "delete", "--group-id", "group1"))
}
