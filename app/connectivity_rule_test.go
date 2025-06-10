package app

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/connectivityrule/v1"
	regionpb "github.com/temporalio/tcld/protogen/api/cloud/region/v1"
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
						ConnectionId:  "test-connection-id",
						Region:        "us-west-2",
						CloudProvider: regionpb.CLOUD_PROVIDER_AWS,
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

// Note, anything after the bool flag will be ignored, and i think that's something we discussed earlier with ocld cmd
// will need to test real cmd to see how it goes.
func (s *ConnectivityRuleTestSuite) TestCreateConnectivityRule() {

	// Test create error
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(nil, errors.New("create error")).Times(1)
	s.Error(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id",
		"--region", "us-west-2",
		"--cloud-provider", "aws", "--is-private", "true"))

	// Test successful create with AWS
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateConnectivityRuleResponse{
		ConnectivityRuleId: "test-connection-id",
	}, nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id", "--region", "us-west-2", "--cloud-provider", "aws", "--is-private", "true"))

	// Test successful create with GCP
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateConnectivityRuleResponse{
		ConnectivityRuleId: "test-connection-id",
	}, nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id",
		"--region", "us-west-2", "--cloud-provider", "gcp",
		"--gcp-project-id", "test-project-id", "--is-private", "true"))

	// Test invalid cloud provider
	s.Error(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id", "--region", "us-west-2", "--cloud-provider", "invalid", "--is-private", "true"))

	// Test missing GCP project ID
	s.Error(s.RunCmd("connectivity-rule", "create",
		"--connection-id", "test-connection-id", "--region", "us-west-2",
		"--cloud-provider", "gcp", "--is-private", "true"))

	// Test public connectivity rule
	s.mockCloudService.EXPECT().CreateConnectivityRule(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateConnectivityRuleResponse{
		ConnectivityRuleId: "test-connection-id",
	}, nil).Times(1)
	s.NoError(s.RunCmd("connectivity-rule", "create"))

}
