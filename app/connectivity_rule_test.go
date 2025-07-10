package app

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/connectivityrule/v1"
	cloudservicemock "github.com/temporalio/tcld/protogen/apimock/cloudservice/v1"
	"github.com/urfave/cli/v2"
)

func TestConnectivityRule(t *testing.T) {
	suite.Run(t, new(ConnectivityRuleTestSuite))
}

type ConnectivityRuleTestSuite struct {
	suite.Suite
	cliApp           *cli.App
	mockCtrl         *gomock.Controller
	mockCloudService *cloudservicemock.MockCloudServiceClient
}

func (s *ConnectivityRuleTestSuite) SetupTest() {
	if !IsFeatureEnabled(ConnectivityRuleFeatureFlag) {
		err := toggleFeature(ConnectivityRuleFeatureFlag)
		s.Require().NoError(err)
	}
	s.mockCtrl = gomock.NewController(s.T())
	s.mockCloudService = cloudservicemock.NewMockCloudServiceClient(s.mockCtrl)
	out, err := NewConnectivityRuleCommand(func(ctx *cli.Context) (*ConnectivityRuleClient, error) {
		return &ConnectivityRuleClient{
			ctx:    context.TODO(),
			client: s.mockCloudService,
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

func (s *ConnectivityRuleTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *ConnectivityRuleTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func getExampleConnectivityRule() *cloudservice.GetConnectivityRuleResponse {
	return &cloudservice.GetConnectivityRuleResponse{
		ConnectivityRule: &connectivityrule.ConnectivityRule{
			Id: "test-rule-id",
			Spec: &connectivityrule.ConnectivityRuleSpec{
				ConnectionType: &connectivityrule.ConnectivityRuleSpec_PrivateRule{
					PrivateRule: &connectivityrule.PrivateConnectivityRule{
						ConnectionId: "test-connection-id",
						Region:       "aws-us-west-2",
					},
				},
			},
		},
	}
}

func getExampleConnectivityRules() *cloudservice.GetConnectivityRulesResponse {
	return &cloudservice.GetConnectivityRulesResponse{
		ConnectivityRules: []*connectivityrule.ConnectivityRule{&connectivityrule.ConnectivityRule{
			Id: "test-rule-id",
			Spec: &connectivityrule.ConnectivityRuleSpec{
				ConnectionType: &connectivityrule.ConnectivityRuleSpec_PrivateRule{
					PrivateRule: &connectivityrule.PrivateConnectivityRule{
						ConnectionId: "test-connection-id",
						Region:       "aws-us-west-2",
					},
				},
			},
		},
		},
	}
}

func (s *ConnectivityRuleTestSuite) TestGetConnectivityRule() {
	// Test missing required flag
	s.Error(s.RunCmd("connectivity-rule", "get"))

	// Test get error
	s.mockCloudService.EXPECT().GetConnectivityRule(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found")).Times(1)
	s.Error(s.RunCmd("connectivity-rule", "get", "--id", "test-rule-id"))

	// Test successful get
	s.mockCloudService.EXPECT().GetConnectivityRule(gomock.Any(), gomock.Any()).Return(getExampleConnectivityRule(), nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "get", "--id", "test-rule-id"))
}

func (s *ConnectivityRuleTestSuite) TestGetConnectivityRules() {
	// Test get error
	s.mockCloudService.EXPECT().GetConnectivityRules(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found")).Times(1)
	s.Error(s.RunCmd("connectivity-rule", "list", "--namespace", "test-namespace"))

	// Test successful get
	s.mockCloudService.EXPECT().GetConnectivityRules(gomock.Any(), gomock.Any()).Return(getExampleConnectivityRules(), nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "list", "--namespace", "test-namespace"))

	// Test successful get without namespace
	s.mockCloudService.EXPECT().GetConnectivityRules(gomock.Any(), gomock.Any()).Return(getExampleConnectivityRules(), nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "list"))
}

func (s *ConnectivityRuleTestSuite) TestCreateConnectivityRule() {
	// Test create error
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(nil, errors.New("create error")).Times(1)
	s.Error(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id",
		"--region", "aws-us-west-2", "--connectivity-type", "private"))

	// Test successful create with AWS
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateConnectivityRuleResponse{
		ConnectivityRuleId: "test-connection-id",
	}, nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id", "--region", "aws-us-west-2", "--connectivity-type", "private"))

	// Test successful create with GCP
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateConnectivityRuleResponse{
		ConnectivityRuleId: "test-connection-id",
	}, nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id",
		"--region", "gcp-us-west2",
		"--gcp-project-id", "test-project-id", "--connectivity-type", "private"))

	// Test invalid cloud provider
	s.Error(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id", "--region", "gcp-us-west-2", "--connectivity-type", "private"))

	// Test missing GCP project ID
	s.Error(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id", "--region", "gcp-us-west2",
		"--connectivity-type", "private"))

	// Test public connectivity rule
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateConnectivityRuleResponse{
		ConnectivityRuleId: "test-connection-id",
	}, nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "create", "--connectivity-type", "public"))

}

func (s *ConnectivityRuleTestSuite) TestDeleteConnectivityRule() {
	// Test missing required flag (id)
	s.Error(s.RunCmd("connectivity-rule", "delete"))

	// Test delete error - first call getConnectivityRule succeeds, then delete fails
	s.mockCloudService.EXPECT().GetConnectivityRule(gomock.Any(), gomock.Any()).
		Return(getExampleConnectivityRule(), nil).Times(1)
	s.mockCloudService.EXPECT().DeleteConnectivityRule(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("delete error")).Times(1)
	s.Error(s.RunCmd("connectivity-rule", "delete", "--id", "test-rule-id"))

	// Test get connectivity rule fails before delete
	s.mockCloudService.EXPECT().GetConnectivityRule(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("not found")).Times(1)
	s.Error(s.RunCmd("connectivity-rule", "delete", "--id", "test-rule-id"))

	// Test successful delete
	s.mockCloudService.EXPECT().GetConnectivityRule(gomock.Any(), gomock.Any()).
		Return(getExampleConnectivityRule(), nil).Times(1)
	s.mockCloudService.EXPECT().DeleteConnectivityRule(gomock.Any(), gomock.Any()).
		Return(&cloudservice.DeleteConnectivityRuleResponse{}, nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "delete", "--id", "test-rule-id"))
}
