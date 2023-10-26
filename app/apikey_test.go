package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	authservicemock "github.com/temporalio/tcld/protogen/apimock/authservice/v1"
	"github.com/urfave/cli/v2"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		arg     string
		want    time.Duration
		wantErr bool
	}{
		{
			arg:  "12h",
			want: 12 * time.Hour,
		},
		{
			arg:     "-24h",
			wantErr: true,
		},
		{
			arg:     "d",
			wantErr: true,
		},
		{
			arg:  "30d",
			want: 30 * 24 * time.Hour,
		},
		{
			arg:     "-2d",
			wantErr: true,
		},
		{
			arg:  "2d12h30m",
			want: 2*24*time.Hour + 12*time.Hour + 30*time.Minute,
		},
		{
			arg:     "-2d12h30m",
			wantErr: true,
		},
		{
			arg:     "2d-12h30m",
			wantErr: true,
		},
		{
			arg:     "abcd12h30m",
			wantErr: true,
		},
		{
			arg:     "2dddd",
			wantErr: true,
		},
		{
			arg:     "2d10h4d30m",
			wantErr: true,
		},
		{
			// technically valid due to 'time.ParseDuration', but
			// note that we require 'd' to come first (if present)
			arg:  "2d55s20m10h",
			want: 58*time.Hour + 20*time.Minute + 55*time.Second,
		},
	}
	for _, test := range tests {
		if got, err := parseDuration(test.arg); err != nil {
			if !test.wantErr {
				t.Fatalf("unexpected error: %v, input: %s", err, test.arg)
			}
		} else if got != test.want {
			t.Fatalf("expected: %s, got: %s", test.want, got)
		}
	}
}

func TestAPIKey(t *testing.T) {
	suite.Run(t, new(APIKeyTestSuite))
}

type APIKeyTestSuite struct {
	suite.Suite
	cliApp          *cli.App
	mockCtrl        *gomock.Controller
	mockAuthService *authservicemock.MockAuthServiceClient
}

func (s *APIKeyTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockAuthService = authservicemock.NewMockAuthServiceClient(s.mockCtrl)
	out, err := NewAPIKeyCommand(func(ctx *cli.Context) (*APIKeyClient, error) {
		return &APIKeyClient{
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

func (s *APIKeyTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *APIKeyTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *APIKeyTestSuite) TestGet() {
	s.Error(s.RunCmd("apikey", "get"))
	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("get apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "get", "--id", "test-apikey-id"))
	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{}, nil).Times(1)
	s.Error(s.RunCmd("apikey", "get", "--id", "test-apikey-id"))
	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{
		ApiKey: &auth.APIKey{
			Id: "test-apikey-id",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("apikey", "get", "--id", "test-apikey-id"))
}

func (s *APIKeyTestSuite) TestList() {
	s.mockAuthService.EXPECT().GetAPIKeys(gomock.Any(), gomock.Any()).Return(nil, errors.New("get apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "list"))
	s.mockAuthService.EXPECT().GetAPIKeys(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeysResponse{
		ApiKeys: []*auth.APIKey{
			{
				Id: "test-apikey-id-1",
			},
		},
		NextPageToken: "token1",
	}, nil).Times(1)
	s.mockAuthService.EXPECT().GetAPIKeys(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeysResponse{
		ApiKeys: []*auth.APIKey{
			{
				Id: "test-apikey-id-2",
			},
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("apikey", "list"))
}

func (s *APIKeyTestSuite) TestCreate() {
	s.Error(s.RunCmd("apikey", "create"))
	s.Error(s.RunCmd("apikey", "create", "--name", "test1"))
	s.Error(s.RunCmd("apikey", "create", "--name", "test1", "--duration", "-24h"))
	s.mockAuthService.EXPECT().CreateAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("create apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "create", "--name", "test1", "--duration", "1h"))
	s.mockAuthService.EXPECT().CreateAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.CreateAPIKeyResponse{
		Id:        "id1",
		SecretKey: "secret1",
		RequestStatus: &request.RequestStatus{
			RequestId: "rid",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("apikey", "create", "--name", "test1", "--duration", "1h"))
	s.mockAuthService.EXPECT().CreateAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.CreateAPIKeyResponse{
		Id:        "id1",
		SecretKey: "secret1",
		RequestStatus: &request.RequestStatus{
			RequestId: "rid",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("apikey", "create", "--name", "test1", "--expiry", time.Now().Add(time.Hour).Format(time.RFC3339)))
}

func (s *APIKeyTestSuite) TestDelete() {
	s.Error(s.RunCmd("apikey", "delete"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("get apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "delete", "--id", "test1"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{
		ApiKey: &auth.APIKey{Id: "test-apikey-id", ResourceVersion: "ver1"},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().DeleteAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("delete apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "delete", "--id", "test1"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{
		ApiKey: &auth.APIKey{Id: "test-apikey-id", ResourceVersion: "ver1"},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().DeleteAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.DeleteAPIKeyResponse{}, nil)
	s.NoError(s.RunCmd("apikey", "delete", "--id", "test1"))
}

func (s *APIKeyTestSuite) TestDisable() {
	s.Error(s.RunCmd("apikey", "disable"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("get apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "disable", "--id", "test1"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{
		ApiKey: &auth.APIKey{Id: "test-apikey-id", ResourceVersion: "ver1", Spec: &auth.APIKeySpec{Disabled: true}},
	}, nil).Times(1)
	s.Error(s.RunCmd("apikey", "disable", "--id", "test1"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{
		ApiKey: &auth.APIKey{Id: "test-apikey-id", ResourceVersion: "ver1", Spec: &auth.APIKeySpec{Disabled: false}},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("delete apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "disable", "--id", "test1"))
}

func (s *APIKeyTestSuite) TestEnable() {
	s.Error(s.RunCmd("apikey", "enable"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("get apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "enable", "--id", "test1"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{
		ApiKey: &auth.APIKey{Id: "test-apikey-id", ResourceVersion: "ver1", Spec: &auth.APIKeySpec{Disabled: false}},
	}, nil).Times(1)
	s.Error(s.RunCmd("apikey", "enable", "--id", "test1"))

	s.mockAuthService.EXPECT().GetAPIKey(gomock.Any(), gomock.Any()).Return(&authservice.GetAPIKeyResponse{
		ApiKey: &auth.APIKey{Id: "test-apikey-id", ResourceVersion: "ver1", Spec: &auth.APIKeySpec{Disabled: true}},
	}, nil).Times(1)
	s.mockAuthService.EXPECT().UpdateAPIKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("delete apikey error")).Times(1)
	s.Error(s.RunCmd("apikey", "enable", "--id", "test1"))
}
