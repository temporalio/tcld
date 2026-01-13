package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/account/v1"
	"github.com/temporalio/tcld/protogen/api/accountservice/v1"
	cloudaccount "github.com/temporalio/tcld/protogen/api/cloud/account/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/operation/v1"
	cloudSink "github.com/temporalio/tcld/protogen/api/cloud/sink/v1"
	"github.com/temporalio/tcld/protogen/api/common/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	accountservicemock "github.com/temporalio/tcld/protogen/apimock/accountservice/v1"
	apimock "github.com/temporalio/tcld/protogen/apimock/cloudservice/v1"
	"github.com/urfave/cli/v2"
)

func TestAccount(t *testing.T) {
	suite.Run(t, new(AccountTestSuite))
}

type AccountTestSuite struct {
	suite.Suite
	cliApp             *cli.App
	mockCtrl           *gomock.Controller
	mockService        *accountservicemock.MockAccountServiceClient
	mockCloudApiClient *apimock.MockCloudServiceClient
}

func (s *AccountTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockService = accountservicemock.NewMockAccountServiceClient(s.mockCtrl)
	s.mockCloudApiClient = apimock.NewMockCloudServiceClient(s.mockCtrl)
	out, err := NewAccountCommand(func(ctx *cli.Context) (*AccountClient, error) {
		return &AccountClient{
			ctx:            context.TODO(),
			client:         s.mockService,
			cloudAPIClient: s.mockCloudApiClient,
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

func (s *AccountTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *AccountTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *AccountTestSuite) TestGet() {
	s.mockService.EXPECT().GetAccount(gomock.Any(), gomock.Any()).Return(nil, errors.New("some error")).Times(1)
	s.Error(s.RunCmd("account", "get"))

	s.mockService.EXPECT().GetAccount(gomock.Any(), gomock.Any()).Return(&accountservice.GetAccountResponse{
		Account: &account.Account{
			State:           account.STATE_UPDATING,
			ResourceVersion: "ver1",
			Spec:            &account.AccountSpec{},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("account", "get"))
}

func (s *AccountTestSuite) TestListRegions() {
	s.mockService.EXPECT().GetRegions(gomock.Any(), gomock.Any()).Return(nil, errors.New("some error")).Times(1)
	s.Error(s.RunCmd("account", "list-regions"))

	s.mockService.EXPECT().GetRegions(gomock.Any(), gomock.Any()).Return(&accountservice.GetRegionsResponse{
		Regions: []*common.Region{
			{RegionId: &common.RegionID{Provider: common.CLOUD_PROVIDER_AWS, Name: "us-west-2"}},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("account", "list-regions"))
}

func (s *AccountTestSuite) TestEnable() {
	type morphGetResp func(*accountservice.GetAccountResponse)
	type morphUpdateReq func(*accountservice.UpdateAccountRequest)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErrMsg string
		expectUpdate morphUpdateReq
	}{
		{
			args: []string{"account", "metrics", "enable"},
			expectGet: func(g *accountservice.GetAccountResponse) {
				g.Account.Spec.Metrics.AcceptedClientCa = ""
			},
			expectErrMsg: "metrics endpoint cannot be enabled until ca certificates have been configured",
		},
		{
			args: []string{"account", "metrics", "enable"},
			expectGet: func(g *accountservice.GetAccountResponse) {
				g.Account.Spec.Metrics.Enabled = true
			},
			expectErrMsg: "metrics endpoint is already enabled",
		},
		{
			args:      []string{"a", "m", "enable"},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.Enabled = true
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := accountservice.GetAccountResponse{
				Account: &account.Account{
					Spec: &account.AccountSpec{
						Metrics: &account.MetricsSpec{
							AcceptedClientCa: "cert1",
						},
					},
					State:           account.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetAccount(gomock.Any(), &accountservice.GetAccountRequest{}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := s.copySpec(getResp.Account.Spec)
				req := accountservice.UpdateAccountRequest{
					Spec:            spec,
					ResourceVersion: getResp.Account.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateAccount(gomock.Any(), &req).
					Return(&accountservice.UpdateAccountResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErrMsg != "" {
				s.Error(err)
				s.ErrorContains(err, tc.expectErrMsg)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestDisable() {
	type morphGetResp func(*accountservice.GetAccountResponse)
	type morphUpdateReq func(*accountservice.UpdateAccountRequest)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErrMsg string
		expectUpdate morphUpdateReq
	}{
		{
			args:         []string{"account", "metrics", "disable"},
			expectGet:    func(g *accountservice.GetAccountResponse) {},
			expectErrMsg: "metrics endpoint is already disabled",
		},
		{
			args: []string{"a", "m", "disable"},
			expectGet: func(g *accountservice.GetAccountResponse) {
				g.Account.Spec.Metrics.Enabled = true
			},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.Enabled = false
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := accountservice.GetAccountResponse{
				Account: &account.Account{
					Spec: &account.AccountSpec{
						Metrics: &account.MetricsSpec{
							AcceptedClientCa: "cert1",
						},
					},
					State:           account.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetAccount(gomock.Any(), &accountservice.GetAccountRequest{}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := s.copySpec(getResp.Account.Spec)
				req := accountservice.UpdateAccountRequest{
					Spec:            spec,
					ResourceVersion: getResp.Account.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateAccount(gomock.Any(), &req).
					Return(&accountservice.UpdateAccountResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErrMsg != "" {
				s.Error(err)
				s.ErrorContains(err, tc.expectErrMsg)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestUpdateCA() {
	type morphGetResp func(*accountservice.GetAccountResponse)
	type morphUpdateReq func(*accountservice.UpdateAccountRequest)

	path := "cafile"
	s.NoError(os.WriteFile(path, []byte("cert2"), 0644))
	defer os.Remove(path)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{
			args: []string{"account", "metrics", "accepted-client-ca"},
		},
		{
			args:      []string{"account", "metrics", "accepted-client-ca", "set"},
			expectErr: true,
		},
		{
			args:      []string{"account", "metrics", "accepted-client-ca", "set"},
			expectErr: true,
		},
		{
			args:      []string{"a", "m", "ca", "set", "--ca-certificate", "cert1"},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectErr: true,
		},
		{
			args:      []string{"a", "m", "ca", "set", "--ca-certificate", "cert2"},
			expectGet: func(g *accountservice.GetAccountResponse) { *g = accountservice.GetAccountResponse{} },
			expectErr: true,
		},
		{
			args:      []string{"a", "m", "ca", "set", "--ca-certificate", "cert2"},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = "cert2"
			},
		},
		{
			args:      []string{"a", "m", "ca", "set", "--ca-certificate", "cert2"},
			expectGet: func(g *accountservice.GetAccountResponse) { g.Account.Spec.Metrics = &account.MetricsSpec{} },
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = "cert2"
			},
		},
		{
			args:      []string{"a", "m", "ca", "set", "--ca-certificate-file", path},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = base64.StdEncoding.EncodeToString([]byte("cert2"))
			},
		},
		{
			args:      []string{"a", "m", "ca", "set", "--ca-certificate-file", "nonexistingfile"},
			expectErr: true,
		},
		{
			args: []string{"a", "m", "ca", "set", "-c", "cert2", "--resource-version", "ver2"},
			expectGet: func(g *accountservice.GetAccountResponse) {
				fmt.Println("1: " + g.Account.GetSpec().GetMetrics().AcceptedClientCa)
			},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = "cert2"
				r.ResourceVersion = "ver2"
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := accountservice.GetAccountResponse{
				Account: &account.Account{
					Spec: &account.AccountSpec{
						Metrics: &account.MetricsSpec{
							AcceptedClientCa: "cert1",
						},
					},
					State:           account.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetAccount(gomock.Any(), &accountservice.GetAccountRequest{}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := s.copySpec(getResp.Account.Spec)
				req := accountservice.UpdateAccountRequest{
					Spec:            spec,
					ResourceVersion: getResp.Account.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateAccount(gomock.Any(), &req).
					Return(&accountservice.UpdateAccountResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestUpdateRemoveCA() {
	cert1raw, err := generateRootX509CAForTest()
	s.NoError(err)
	cert2raw, err := generateRootX509CAForTest()
	s.NoError(err)
	cert3raw, err := generateRootX509CAForTest()
	s.NoError(err)

	cert1 := base64.StdEncoding.EncodeToString([]byte(cert1raw))
	cert2 := base64.StdEncoding.EncodeToString([]byte(cert2raw))
	cert12 := base64.StdEncoding.EncodeToString([]byte(cert1raw + "\n" + cert2raw))
	cert3 := base64.StdEncoding.EncodeToString([]byte(cert3raw))

	cs, err := parseCertificates(cert2)
	s.NoError(err)
	cert2fingerprint := cs[0].Fingerprint

	cs, err = parseCertificates(cert3)
	s.NoError(err)
	cert3fingerprint := cs[0].Fingerprint

	type morphGetResp func(*accountservice.GetAccountResponse)
	type morphUpdateReq func(*accountservice.UpdateAccountRequest)

	path := "cafile"
	s.NoError(os.WriteFile(path, []byte(cert2raw+"\n"), 0644))
	defer os.Remove(path)

	tests := []struct {
		name         string
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{
			name:      "err no cert",
			expectGet: func(g *accountservice.GetAccountResponse) {},
			args:      []string{"account", "metrics", "accepted-client-ca", "remove"},
			expectErr: true,
		},
		{
			name:      "remove 1st cert",
			args:      []string{"a", "m", "ca", "remove", "--ca-certificate", cert1},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert2
			},
		},
		{
			name:      "remove 2nd cert",
			args:      []string{"a", "m", "ca", "r", "--ca-certificate", cert2},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert1
			},
		},
		{
			name:      "remove unknown cert",
			args:      []string{"a", "m", "ca", "r", "--ca-certificate", cert3},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectErr: true,
		},
		{
			name: "err empty namespace",
			args: []string{"a", "m", "ca", "remove", "--ca-certificate", cert2},
			expectGet: func(g *accountservice.GetAccountResponse) {
				*g = accountservice.GetAccountResponse{}
			},
			expectErr: true,
		},
		{
			name:      "empty cert - remove 1 cert",
			args:      []string{"a", "m", "ca", "r", "--ca-certificate", cert2},
			expectGet: func(g *accountservice.GetAccountResponse) { g.Account.Spec.Metrics.AcceptedClientCa = "" },
			expectErr: true,
		},
		{
			name:      "remove 1 cert from path",
			args:      []string{"a", "m", "ca", "r", "--ca-certificate-file", path},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert1
			},
		},
		{
			name:      "err remove from nonexistent path",
			expectGet: func(g *accountservice.GetAccountResponse) {},
			args:      []string{"a", "m", "ca", "r", "--ca-certificate-file", "nonexistingfile"},
			expectErr: true,
		},
		{
			name:      "remove fingerprint",
			args:      []string{"a", "m", "ca", "r", "--ca-certificate-fingerprint", cert2fingerprint},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert1
			},
		},
		{
			name:      "err remove unknown fingerprint",
			expectGet: func(g *accountservice.GetAccountResponse) {},
			args:      []string{"a", "m", "ca", "r", "--fp", cert3fingerprint},
			expectErr: true,
		},
		{
			name:      "custom resource version",
			args:      []string{"a", "m", "ca", "r", "-c", cert2, "--resource-version", "ver2"},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert1
				r.ResourceVersion = "ver2"
			},
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			getResp := accountservice.GetAccountResponse{
				Account: &account.Account{
					Spec: &account.AccountSpec{
						Metrics: &account.MetricsSpec{
							AcceptedClientCa: cert12,
						},
					},
					State:           account.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetAccount(gomock.Any(), &accountservice.GetAccountRequest{}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := s.copySpec(getResp.Account.Spec)
				req := accountservice.UpdateAccountRequest{
					Spec:            spec,
					ResourceVersion: getResp.Account.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateAccount(gomock.Any(), &req).
					Return(&accountservice.UpdateAccountResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestUpdateAddCA() {
	cert1raw, err := generateRootX509CAForTest()
	s.NoError(err)
	cert2raw, err := generateRootX509CAForTest()
	s.NoError(err)

	cert1 := base64.StdEncoding.EncodeToString([]byte(cert1raw))
	cert2 := base64.StdEncoding.EncodeToString([]byte(cert2raw))
	cert12 := base64.StdEncoding.EncodeToString([]byte(cert1raw + "\n" + cert2raw))

	s.NoError(err)

	type morphGetResp func(*accountservice.GetAccountResponse)
	type morphUpdateReq func(*accountservice.UpdateAccountRequest)

	path := "cafile"
	s.NoError(os.WriteFile(path, []byte(cert2raw+"\n"), 0644))
	defer os.Remove(path)

	tests := []struct {
		name         string
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{
			name:      "err no cert",
			args:      []string{"account", "metrics", "accepted-client-ca", "add"},
			expectErr: true,
		},
		{
			name:      "err same cert",
			args:      []string{"a", "m", "ca", "add", "--ca-certificate", cert1},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectErr: true,
		},
		{
			name: "err empty namespace",
			args: []string{"a", "m", "ca", "add", "--ca-certificate", cert2},
			expectGet: func(g *accountservice.GetAccountResponse) {
				*g = accountservice.GetAccountResponse{}
			},
			expectErr: true,
		},
		{
			name:      "add 1 cert",
			args:      []string{"a", "m", "ca", "add", "--ca-certificate", cert2},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert12
			},
		},
		{
			name:      "empty cert - add 1 cert",
			args:      []string{"a", "m", "ca", "add", "--ca-certificate", cert2},
			expectGet: func(g *accountservice.GetAccountResponse) { g.Account.Spec.Metrics.AcceptedClientCa = "" },
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert2
			},
		},
		{
			name:      "add 1 cert from path",
			args:      []string{"a", "m", "ca", "add", "--ca-certificate-file", path},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert12
			},
		},
		{
			name:      "err from nonexistent path",
			args:      []string{"a", "m", "ca", "add", "--ca-certificate-file", "nonexistingfile"},
			expectErr: true,
		},
		{
			name:      "custom resource version",
			args:      []string{"a", "m", "ca", "add", "-c", cert2, "--resource-version", "ver2"},
			expectGet: func(g *accountservice.GetAccountResponse) {},
			expectUpdate: func(r *accountservice.UpdateAccountRequest) {
				r.Spec.Metrics.AcceptedClientCa = cert12
				r.ResourceVersion = "ver2"
			},
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			getResp := accountservice.GetAccountResponse{
				Account: &account.Account{
					Spec: &account.AccountSpec{
						Metrics: &account.MetricsSpec{
							AcceptedClientCa: cert1,
						},
					},
					State:           account.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetAccount(gomock.Any(), &accountservice.GetAccountRequest{}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := s.copySpec(getResp.Account.Spec)
				req := accountservice.UpdateAccountRequest{
					Spec:            spec,
					ResourceVersion: getResp.Account.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateAccount(gomock.Any(), &req).
					Return(&accountservice.UpdateAccountResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) copySpec(spec *account.AccountSpec) *account.AccountSpec {
	bytes, err := json.Marshal(spec)
	s.NoError(err)

	var copy account.AccountSpec
	s.NoError(json.Unmarshal(bytes, &copy))
	return &copy
}

func (s *AccountTestSuite) TestCreateAuditLogSink() {
	tests := []struct {
		name          string
		args          []string
		expectErr     bool
		expectRequest cloudservice.CreateAccountAuditLogSinkRequest
		createError   error
	}{
		{
			name: "kinesis audit log sink",
			args: []string{"a", "al", "kinesis", "create", "--sink-name", "audit_log_01", "--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1"},
			expectErr: false,
			expectRequest: cloudservice.CreateAccountAuditLogSinkRequest{
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
						KinesisSink: &cloudSink.KinesisSpec{
							RoleName:       "TestRole",
							DestinationUri: "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
							Region:         "us-east-1",
						},
					},
				},
			},
		},
		{
			name: "kinesis audit log sink with error",
			args: []string{"a", "al", "kinesis", "create", "--sink-name", "audit_log_01",
				"--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1"},
			expectErr: true,
			expectRequest: cloudservice.CreateAccountAuditLogSinkRequest{
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
						KinesisSink: &cloudSink.KinesisSpec{
							RoleName:       "TestRole",
							DestinationUri: "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
							Region:         "us-east-1",
						},
					},
				},
			},
			createError: fmt.Errorf("error"),
		},
		{
			name: "kinesis audit log sink missing role name",
			args: []string{"a", "al", "kinesis", "create", "--sink-name", "audit_log_01",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1"},
			expectErr: true,
		},
		{
			name: "kinesis audit log sink missing destination uri",
			args: []string{"a", "al", "kinesis", "create", "--sink-name", "audit_log_01",
				"--role-name", "TestRole",
				"--region", "us-east-1"},
			expectErr: true,
		},
		{
			name: "kinesis audit log sink missing region",
			args: []string{"a", "al", "kinesis", "create", "--sink-name", "audit_log_01",
				"--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream"},
			expectErr: true,
		},
		{
			name: "pubsub audit log sink",
			args: []string{"a", "al", "pubsub", "create", "--sink-name", "audit_log_01",
				"--service-account-email", "123456789012@TestProject.iam.gserviceaccount.com", "--topic-name", "TestTopic"},
			expectErr: false,
			expectRequest: cloudservice.CreateAccountAuditLogSinkRequest{
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_PubSubSink{
						PubSubSink: &cloudSink.PubSubSpec{
							ServiceAccountId: "123456789012",
							TopicName:        "TestTopic",
							GcpProjectId:     "TestProject",
						},
					},
				},
			},
		},
		{
			name: "pubsub audit log sink missing service account email",
			args: []string{"a", "al", "pubsub", "create", "--sink-name", "audit_log_01",
				"--topic-name", "TestTopic"},
			expectErr: true,
		},
		{
			name: "pubsub audit log sink missing topic name",
			args: []string{"a", "al", "pubsub", "create", "--sink-name", "audit_log_01",
				"--service-account-email", "123456789012@TestProject.iam.gserviceaccount.com"},
			expectErr: true,
		},
	}
	for _, tc := range tests {
		s.Run(tc.name, func() {
			if tc.expectRequest != (cloudservice.CreateAccountAuditLogSinkRequest{}) {
				s.mockCloudApiClient.EXPECT().CreateAccountAuditLogSink(gomock.Any(), &tc.expectRequest).Return(&cloudservice.CreateAccountAuditLogSinkResponse{
					AsyncOperation: &operation.AsyncOperation{
						Id: "123",
					},
				}, tc.createError).Times(1)
			}
			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestUpdateAuditLogSink() {
	tests := []struct {
		name             string
		args             []string
		expectErr        bool
		expectRequest    cloudservice.UpdateAccountAuditLogSinkRequest
		expectGetRequest bool
		updateError      error
		getSinkError     error
	}{
		{
			name: "kinesis audit log sink",
			args: []string{"a", "al", "kinesis", "update", "--sink-name", "audit_log_01",
				"--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1", "--enabled", "true"},
			expectErr:        false,
			expectGetRequest: true,
			expectRequest: cloudservice.UpdateAccountAuditLogSinkRequest{
				ResourceVersion: "123",
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
						KinesisSink: &cloudSink.KinesisSpec{
							RoleName:       "TestRole",
							DestinationUri: "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
							Region:         "us-east-1",
						},
					},
				},
			},
		},
		{
			name: "audit log sink get sink error",
			args: []string{"a", "al", "kinesis", "update", "--sink-name", "audit_log_01",
				"--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1", "--enabled", "true"},
			expectErr:        true,
			expectGetRequest: true,
			expectRequest: cloudservice.UpdateAccountAuditLogSinkRequest{
				ResourceVersion: "123",
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
						KinesisSink: &cloudSink.KinesisSpec{
							RoleName:       "TestRole",
							DestinationUri: "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
							Region:         "us-east-1",
						},
					},
				},
			},
			getSinkError: fmt.Errorf("error"),
		},
		{
			name: "audit log sink update error",
			args: []string{"a", "al", "kinesis", "update", "--sink-name", "audit_log_01",
				"--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1", "--enabled", "true"},
			expectErr:        true,
			expectGetRequest: true,
			expectRequest: cloudservice.UpdateAccountAuditLogSinkRequest{
				ResourceVersion: "123",
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
						KinesisSink: &cloudSink.KinesisSpec{
							RoleName:       "TestRole",
							DestinationUri: "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
							Region:         "us-east-1",
						},
					},
				},
			},
			updateError: fmt.Errorf("error"),
		},
		{
			name: "pubsub audit log sink",
			args: []string{"a", "al", "pubsub", "update", "--sink-name", "audit_log_01",
				"--enabled", "true",
				"--service-account-email", "123456789012@TestProject.iam.gserviceaccount.com", "--topic-name", "TestTopic"},
			expectErr:        false,
			expectGetRequest: true,
			expectRequest: cloudservice.UpdateAccountAuditLogSinkRequest{
				ResourceVersion: "123",
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_PubSubSink{
						PubSubSink: &cloudSink.PubSubSpec{
							ServiceAccountId: "123456789012",
							TopicName:        "TestTopic",
							GcpProjectId:     "TestProject",
						},
					},
				},
			},
		},
		{
			name: "update sink uses provided resource version",
			args: []string{"a", "al", "pubsub", "update", "--sink-name", "audit_log_01",
				"--enabled", "true",
				"--service-account-email", "123456789012@TestProject.iam.gserviceaccount.com", "--topic-name", "TestTopic", "--resource-version", "345"},
			expectErr:        false,
			expectGetRequest: true,
			expectRequest: cloudservice.UpdateAccountAuditLogSinkRequest{
				ResourceVersion: "345",
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "audit_log_01",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_PubSubSink{
						PubSubSink: &cloudSink.PubSubSpec{
							ServiceAccountId: "123456789012",
							TopicName:        "TestTopic",
							GcpProjectId:     "TestProject",
						},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		s.Run(tc.name, func() {
			if tc.expectRequest != (cloudservice.UpdateAccountAuditLogSinkRequest{}) {
				if tc.expectGetRequest {
					sinkType := ""
					if len(tc.args) >= 3 {
						sinkType = tc.args[2]
					}

					var mockSink *cloudaccount.AuditLogSink
					switch sinkType {
					case "kinesis":
						mockSink = &cloudaccount.AuditLogSink{
							ResourceVersion: "123",
							Spec: &cloudaccount.AuditLogSinkSpec{
								Name:    "audit_log_01",
								Enabled: false,
								SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
									KinesisSink: &cloudSink.KinesisSpec{
										RoleName:       "OldRole",
										DestinationUri: "old-uri",
										Region:         "old-region",
									},
								},
							},
						}
					case "pubsub":
						mockSink = &cloudaccount.AuditLogSink{
							ResourceVersion: "123",
							Spec: &cloudaccount.AuditLogSinkSpec{
								Name:    "audit_log_01",
								Enabled: false,
								SinkType: &cloudaccount.AuditLogSinkSpec_PubSubSink{
									PubSubSink: &cloudSink.PubSubSpec{
										ServiceAccountId: "old-sa",
										TopicName:        "old-topic",
										GcpProjectId:     "old-project",
									},
								},
							},
						}

					}
					s.mockCloudApiClient.EXPECT().GetAccountAuditLogSink(gomock.Any(), &cloudservice.GetAccountAuditLogSinkRequest{
						Name: "audit_log_01",
					}).Return(&cloudservice.GetAccountAuditLogSinkResponse{
						Sink: mockSink,
					}, tc.getSinkError).Times(1)
				}
				if tc.getSinkError == nil {
					s.mockCloudApiClient.EXPECT().UpdateAccountAuditLogSink(gomock.Any(), &tc.expectRequest).Return(&cloudservice.UpdateAccountAuditLogSinkResponse{
						AsyncOperation: &operation.AsyncOperation{
							Id: "123",
						},
					}, tc.updateError).Times(1)
				}
			}
			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestDeleteAuditLogSink() {
	tests := []struct {
		name             string
		args             []string
		expectErr        bool
		expectRequest    cloudservice.DeleteAccountAuditLogSinkRequest
		expectGetRequest bool
		deleteError      error
		getSinkError     error
	}{
		{
			name:             "delete audit log sink success",
			args:             []string{"a", "al", "kinesis", "delete", "--sink-name", "audit_log_01"},
			expectErr:        false,
			expectGetRequest: true,
			expectRequest: cloudservice.DeleteAccountAuditLogSinkRequest{
				ResourceVersion: "123",
				Name:            "audit_log_01",
			},
		},
		{
			name:      "delete audit log sink uses provided resource version",
			args:      []string{"a", "al", "kinesis", "delete", "--sink-name", "audit_log_01", "--resource-version", "345"},
			expectErr: false,
			expectRequest: cloudservice.DeleteAccountAuditLogSinkRequest{
				ResourceVersion: "345",
				Name:            "audit_log_01",
			},
		},
		{
			name:             "delete audit log sink get sink error",
			args:             []string{"a", "al", "kinesis", "delete", "--sink-name", "audit_log_01"},
			expectErr:        true,
			expectGetRequest: true,
			expectRequest: cloudservice.DeleteAccountAuditLogSinkRequest{
				ResourceVersion: "123",
				Name:            "audit_log_01",
			},
			getSinkError: fmt.Errorf("error"),
		},
		{
			name:             "delete audit log sink delete error",
			args:             []string{"a", "al", "kinesis", "delete", "--sink-name", "audit_log_01"},
			expectErr:        true,
			expectGetRequest: true,
			expectRequest: cloudservice.DeleteAccountAuditLogSinkRequest{
				ResourceVersion: "123",
				Name:            "audit_log_01",
			},
			deleteError: fmt.Errorf("error"),
		},
	}
	for _, tc := range tests {
		s.Run(tc.name, func() {
			if tc.expectRequest != (cloudservice.DeleteAccountAuditLogSinkRequest{}) {
				if tc.expectGetRequest {
					s.mockCloudApiClient.EXPECT().GetAccountAuditLogSink(gomock.Any(), &cloudservice.GetAccountAuditLogSinkRequest{
						Name: "audit_log_01",
					}).Return(&cloudservice.GetAccountAuditLogSinkResponse{
						Sink: &cloudaccount.AuditLogSink{
							ResourceVersion: "123",
						},
					}, tc.getSinkError).Times(1)
				}
				if tc.getSinkError == nil {
					s.mockCloudApiClient.EXPECT().DeleteAccountAuditLogSink(gomock.Any(), &tc.expectRequest).Return(&cloudservice.DeleteAccountAuditLogSinkResponse{
						AsyncOperation: &operation.AsyncOperation{
							Id: "123",
						},
					}, tc.deleteError).Times(1)
				}
			}
			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestValidateAuditLogSink() {
	tests := []struct {
		name          string
		args          []string
		expectErr     bool
		expectRequest cloudservice.ValidateAccountAuditLogSinkRequest
		validateError error
	}{
		{
			name: "kinesis audit log sink",
			args: []string{"a", "al", "kinesis", "validate",
				"--sink-name", "test-sink",
				"--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1"},
			expectErr: false,
			expectRequest: cloudservice.ValidateAccountAuditLogSinkRequest{
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "test-sink",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
						KinesisSink: &cloudSink.KinesisSpec{
							RoleName:       "TestRole",
							DestinationUri: "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
							Region:         "us-east-1",
						},
					},
				},
			},
		},
		{
			name: "kinesis audit log sink with error",
			args: []string{"a", "al", "kinesis", "validate",
				"--sink-name", "test-sink",
				"--role-name", "TestRole",
				"--destination-uri", "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
				"--region", "us-east-1"},
			expectErr: true,
			expectRequest: cloudservice.ValidateAccountAuditLogSinkRequest{
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "test-sink",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_KinesisSink{
						KinesisSink: &cloudSink.KinesisSpec{
							RoleName:       "TestRole",
							DestinationUri: "arn:aws:kinesis:us-east-1:123456789012:stream/TestStream",
							Region:         "us-east-1",
						},
					},
				},
			},
			validateError: fmt.Errorf("error"),
		},
		{
			name: "pubsub audit log sink",
			args: []string{"a", "al", "pubsub", "validate",
				"--sink-name", "test-sink",
				"--service-account-email", "123456789012@TestProject.iam.gserviceaccount.com", "--topic-name", "TestTopic"},
			expectErr: false,
			expectRequest: cloudservice.ValidateAccountAuditLogSinkRequest{
				Spec: &cloudaccount.AuditLogSinkSpec{
					Name:    "test-sink",
					Enabled: true,
					SinkType: &cloudaccount.AuditLogSinkSpec_PubSubSink{
						PubSubSink: &cloudSink.PubSubSpec{
							ServiceAccountId: "123456789012",
							TopicName:        "TestTopic",
							GcpProjectId:     "TestProject",
						},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		s.Run(tc.name, func() {
			if tc.expectRequest != (cloudservice.ValidateAccountAuditLogSinkRequest{}) {
				s.mockCloudApiClient.EXPECT().ValidateAccountAuditLogSink(gomock.Any(), &tc.expectRequest).Return(&cloudservice.ValidateAccountAuditLogSinkResponse{}, tc.validateError).Times(1)
			}
			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestListAuditLogSinks() {
	tests := []struct {
		name          string
		args          []string
		expectErr     bool
		expectRequest cloudservice.GetAccountAuditLogSinksRequest
		listError     error
	}{
		{
			name:          "list sinks succeeds",
			args:          []string{"a", "al", "kinesis", "list"},
			expectErr:     false,
			expectRequest: cloudservice.GetAccountAuditLogSinksRequest{},
		},
		{
			name:          "list sinks with error",
			args:          []string{"a", "al", "kinesis", "list"},
			expectErr:     true,
			expectRequest: cloudservice.GetAccountAuditLogSinksRequest{},
			listError:     fmt.Errorf("error"),
		},
	}
	for _, tc := range tests {
		s.Run(tc.name, func() {
			s.mockCloudApiClient.EXPECT().GetAccountAuditLogSinks(gomock.Any(), gomock.Any()).Return(&cloudservice.GetAccountAuditLogSinksResponse{}, tc.listError).Times(1)
			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestGetAuditLogSink() {
	tests := []struct {
		name          string
		args          []string
		expectErr     bool
		expectRequest cloudservice.GetAccountAuditLogSinkRequest
		getError      error
	}{
		{
			name:      "get sink succeeds",
			args:      []string{"a", "al", "kinesis", "get", "--sink-name", "audit_log_01"},
			expectErr: false,
			expectRequest: cloudservice.GetAccountAuditLogSinkRequest{
				Name: "audit_log_01",
			},
		},
		{
			name:      "get sink with error",
			args:      []string{"a", "al", "kinesis", "get", "--sink-name", "audit_log_01"},
			expectErr: true,
			expectRequest: cloudservice.GetAccountAuditLogSinkRequest{
				Name: "audit_log_01",
			},
			getError: fmt.Errorf("error"),
		},
	}
	for _, tc := range tests {
		s.Run(tc.name, func() {
			s.mockCloudApiClient.EXPECT().GetAccountAuditLogSink(gomock.Any(), &tc.expectRequest).Return(&cloudservice.GetAccountAuditLogSinkResponse{}, tc.getError).Times(1)
			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *AccountTestSuite) TestListAuditLogs() {
	startTime := time.Date(2024, 1, 13, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2024, 1, 14, 0, 0, 0, 0, time.UTC)
	startTimeProto, _ := types.TimestampProto(startTime)
	endTimeProto, _ := types.TimestampProto(endTime)

	tests := []struct {
		name          string
		args          []string
		expectErr     bool
		expectRequest func() *cloudservice.GetAuditLogsRequest
		queryError    error
	}{
		{
			name:      "query with both start and end time succeeds",
			args:      []string{"a", "al", "list", "--start-time", "2024-01-13T00:00:00Z", "--end-time", "2024-01-14T00:00:00Z"},
			expectErr: false,
			expectRequest: func() *cloudservice.GetAuditLogsRequest {
				return &cloudservice.GetAuditLogsRequest{
					StartTimeInclusive: startTimeProto,
					EndTimeExclusive:   endTimeProto,
					PageSize:           DefaultPageSize,
					PageToken:          "",
				}
			},
		},
		{
			name:      "query with aliases st and et succeeds",
			args:      []string{"a", "al", "list", "--st", "2024-01-13T00:00:00Z", "--et", "2024-01-14T00:00:00Z"},
			expectErr: false,
			expectRequest: func() *cloudservice.GetAuditLogsRequest {
				return &cloudservice.GetAuditLogsRequest{
					StartTimeInclusive: startTimeProto,
					EndTimeExclusive:   endTimeProto,
					PageSize:           DefaultPageSize,
					PageToken:          "",
				}
			},
		},
		{
			name:      "query with only start time succeeds",
			args:      []string{"a", "al", "list", "--st", "2024-01-13T00:00:00Z"},
			expectErr: false,
			expectRequest: func() *cloudservice.GetAuditLogsRequest {
				return &cloudservice.GetAuditLogsRequest{
					StartTimeInclusive: startTimeProto,
					PageSize:           DefaultPageSize,
					PageToken:          "",
				}
			},
		},
		{
			name:      "query with only end time succeeds",
			args:      []string{"a", "al", "list", "--et", "2024-01-14T00:00:00Z"},
			expectErr: false,
			expectRequest: func() *cloudservice.GetAuditLogsRequest {
				return &cloudservice.GetAuditLogsRequest{
					EndTimeExclusive: endTimeProto,
					PageSize:         DefaultPageSize,
					PageToken:        "",
				}
			},
		},
		{
			name:      "query with page size and token succeeds",
			args:      []string{"a", "al", "list", "--st", "2024-01-13T00:00:00Z", "--page-size", "50", "--page-token", "token123"},
			expectErr: false,
			expectRequest: func() *cloudservice.GetAuditLogsRequest {
				return &cloudservice.GetAuditLogsRequest{
					StartTimeInclusive: startTimeProto,
					PageSize:           50,
					PageToken:          "token123",
				}
			},
		},
		{
			name:      "query without time filters succeeds",
			args:      []string{"a", "al", "list"},
			expectErr: false,
			expectRequest: func() *cloudservice.GetAuditLogsRequest {
				return &cloudservice.GetAuditLogsRequest{
					PageSize:  DefaultPageSize,
					PageToken: "",
				}
			},
		},
		{
			name:      "query with invalid timestamp format fails",
			args:      []string{"a", "al", "list", "--st", "invalid-date"},
			expectErr: true,
		},
		{
			name:      "query with API error fails",
			args:      []string{"a", "al", "list", "--st", "2024-01-13T00:00:00Z"},
			expectErr: true,
			expectRequest: func() *cloudservice.GetAuditLogsRequest {
				return &cloudservice.GetAuditLogsRequest{
					StartTimeInclusive: startTimeProto,
					PageSize:           DefaultPageSize,
					PageToken:          "",
				}
			},
			queryError: fmt.Errorf("API error"),
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			if tc.expectRequest != nil {
				expectedReq := tc.expectRequest()
				s.mockCloudApiClient.EXPECT().
					GetAuditLogs(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, req *cloudservice.GetAuditLogsRequest, opts ...interface{}) (*cloudservice.GetAuditLogsResponse, error) {
						s.Equal(expectedReq.PageSize, req.PageSize)
						s.Equal(expectedReq.PageToken, req.PageToken)
						if expectedReq.StartTimeInclusive != nil {
							s.NotNil(req.StartTimeInclusive)
							s.Equal(expectedReq.StartTimeInclusive.Seconds, req.StartTimeInclusive.Seconds)
						} else {
							s.Nil(req.StartTimeInclusive)
						}
						if expectedReq.EndTimeExclusive != nil {
							s.NotNil(req.EndTimeExclusive)
							s.Equal(expectedReq.EndTimeExclusive.Seconds, req.EndTimeExclusive.Seconds)
						} else {
							s.Nil(req.EndTimeExclusive)
						}
						return &cloudservice.GetAuditLogsResponse{}, tc.queryError
					}).
					Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}
