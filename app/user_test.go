package app

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	authservicemock "github.com/temporalio/tcld/protogen/apimock/authservice/v1"
	"github.com/urfave/cli/v2"
	"testing"
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
	AutoConfirmFlag.Value = true
	s.cliApp = &cli.App{
		Name:     "test",
		Commands: []*cli.Command{out.Command},
		Flags: []cli.Flag{
			AutoConfirmFlag,
		},
	}
}

func (s *UserTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *UserTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *UserTestSuite) TestGet() {
	s.Error(s.RunCmd("user", "get"))
	s.Error(s.RunCmd("user", "get", "--user-email", "test@example.com", "--user-id", "test-user-id"))
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "test@example.com",
			},
		},
	}, nil).Times(2)
	s.NoError(s.RunCmd("user", "get", "--user-email", "test@example.com"))
	s.NoError(s.RunCmd("user", "get", "--user-id", "test-user-id"))
}
