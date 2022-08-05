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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/api/temporalcloudapi/accountservicemock/v1"
	"github.com/temporalio/tcld/protogen/api/account/v1"
	"github.com/temporalio/tcld/protogen/api/accountservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	"github.com/urfave/cli/v2"
)

func TestAccount(t *testing.T) {
	suite.Run(t, new(AccountTestSuite))
}

type AccountTestSuite struct {
	suite.Suite
	cliApp      *cli.App
	mockCtrl    *gomock.Controller
	mockService *accountservicemock.MockAccountServiceClient
}

func (s *AccountTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockService = accountservicemock.NewMockAccountServiceClient(s.mockCtrl)
	out, err := NewAccountCommand(func(ctx *cli.Context) (*AccountClient, error) {
		return &AccountClient{
			ctx:    context.TODO(),
			client: s.mockService,
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
