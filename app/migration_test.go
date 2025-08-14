package app

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	cloudNamespace "github.com/temporalio/tcld/protogen/api/cloud/namespace/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/operation/v1"
	apimock "github.com/temporalio/tcld/protogen/apimock/cloudservice/v1"
	"github.com/urfave/cli/v2"
)

func TestMigration(t *testing.T) {
	suite.Run(t, new(MigrationTestSuite))
}

type MigrationTestSuite struct {
	suite.Suite
	cliApp             *cli.App
	mockCtrl           *gomock.Controller
	mockCloudApiClient *apimock.MockCloudServiceClient
}

func (s *MigrationTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockCloudApiClient = apimock.NewMockCloudServiceClient(s.mockCtrl)

	out, err := NewMigrationCommand(func(ctx *cli.Context) (*MigrationClient, error) {
		return &MigrationClient{
			ctx:    context.TODO(),
			client: s.mockCloudApiClient,
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

func (s *MigrationTestSuite) SetupSubTest() {
	s.SetupTest()
}

func (s *MigrationTestSuite) RunCmd(args []string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *MigrationTestSuite) AfterTest() {
	s.mockCtrl.Finish()
}

func (s *MigrationTestSuite) TearDownSubTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *MigrationTestSuite) TestGet() {
	testcases := []struct {
		name     string
		cmd      []string
		expReq   *cloudservice.GetMigrationRequest
		mockResp *cloudservice.GetMigrationResponse
		mockErr  error

		expErr string
	}{
		{
			name:   "missing id",
			cmd:    []string{"migration", "get"},
			expErr: `Required flag "id" not set`,
		},
		{
			name: "api error",
			cmd:  []string{"migration", "get", "--id", "abc"},
			expReq: &cloudservice.GetMigrationRequest{
				MigrationId: "abc",
			},
			mockErr: errors.New("some err"),
			expErr:  "some err",
		},
		{
			name: "success",
			cmd:  []string{"migration", "get", "--id", "abc"},
			expReq: &cloudservice.GetMigrationRequest{
				MigrationId: "abc",
			},
			mockResp: &cloudservice.GetMigrationResponse{
				Migration: s.makeMigration("abc"),
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			if tc.expReq != nil {
				s.mockCloudApiClient.EXPECT().GetMigration(gomock.Any(), tc.expReq).
					Return(tc.mockResp, tc.mockErr).Times(1)
			}

			err := s.RunCmd(tc.cmd)
			if len(tc.expErr) != 0 {
				s.ErrorContains(err, tc.expErr)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *MigrationTestSuite) TestList() {
	testcases := []struct {
		name     string
		cmd      []string
		expReq   []*cloudservice.GetMigrationsRequest
		mockResp []*cloudservice.GetMigrationsResponse
		mockErr  []error

		expErr string
	}{
		{
			name: "api error",
			cmd:  []string{"migration", "list"},
			expReq: []*cloudservice.GetMigrationsRequest{
				{},
			},
			mockResp: []*cloudservice.GetMigrationsResponse{
				nil,
			},
			mockErr: []error{
				errors.New("some err"),
			},
			expErr: "some err",
		},
		{
			name: "api error on page 2",
			cmd:  []string{"migration", "list"},
			expReq: []*cloudservice.GetMigrationsRequest{
				{},
				{PageToken: "page2"},
			},
			mockResp: []*cloudservice.GetMigrationsResponse{
				{
					Migrations: []*cloudNamespace.Migration{
						s.makeMigration("abc"),
					},
					NextPageToken: "page2",
				},
				nil,
			},
			mockErr: []error{
				nil,
				errors.New("page 2 err"),
			},
			expErr: "page 2 err",
		},
		{
			name: "1 page - success",
			cmd:  []string{"migration", "list"},
			expReq: []*cloudservice.GetMigrationsRequest{
				{},
			},
			mockResp: []*cloudservice.GetMigrationsResponse{
				{
					Migrations: []*cloudNamespace.Migration{
						s.makeMigration("abc"),
					},
				},
			},
			mockErr: []error{
				nil,
			},
		},
		{
			name: "2 pages - success",
			cmd:  []string{"migration", "list"},
			expReq: []*cloudservice.GetMigrationsRequest{
				{},
				{PageToken: "page2"},
			},
			mockResp: []*cloudservice.GetMigrationsResponse{
				{
					Migrations: []*cloudNamespace.Migration{
						s.makeMigration("abc"),
					},
					NextPageToken: "page2",
				},
				{
					Migrations: []*cloudNamespace.Migration{
						s.makeMigration("def"),
					},
					NextPageToken: "",
				},
			},
			mockErr: []error{
				nil,
				nil,
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			s.Require().Equal(len(tc.expReq), len(tc.mockResp))
			s.Require().Equal(len(tc.expReq), len(tc.mockErr))

			for i := range tc.expReq {
				s.mockCloudApiClient.EXPECT().GetMigrations(gomock.Any(), tc.expReq[i]).
					Return(tc.mockResp[i], tc.mockErr[i]).Times(1)
			}

			err := s.RunCmd(tc.cmd)
			if len(tc.expErr) != 0 {
				s.ErrorContains(err, tc.expErr)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *MigrationTestSuite) TestStart() {
	fullTestCmd := []string{
		"migration", "start",
		"--endpoint-id", "ep-123",
		"--source-namespace", "src-ns",
		"--target-namespace", "tgt-ns",
		"--request-id", "req-xyz",
	}
	fullTestSpec := &cloudNamespace.MigrationSpec{
		MigrationEndpointId: "ep-123",
		Spec: &cloudNamespace.MigrationSpec_ToCloudSpec{
			ToCloudSpec: &cloudNamespace.MigrationToCloudSpec{
				SourceNamespace: "src-ns",
				TargetNamespace: "tgt-ns",
			},
		},
	}

	testcases := []struct {
		name     string
		cmd      []string
		expReq   *cloudservice.StartMigrationRequest
		mockResp *cloudservice.StartMigrationResponse
		mockErr  error

		expErr string
	}{
		{
			name: "missing endpoint-id",
			cmd: []string{
				"migration", "start",
				"--source-namespace", "src-ns",
				"--target-namespace", "tgt-ns",
			},
			expErr: `Required flag "endpoint-id" not set`,
		},
		{
			name: "missing source-namespace",
			cmd: []string{
				"migration", "start",
				"--endpoint-id", "ep-123",
				"--target-namespace", "tgt-ns",
			},
			expErr: `Required flag "source-namespace" not set`,
		},
		{
			name: "mising target-namespace",
			cmd: []string{
				"migration", "start",
				"--endpoint-id", "ep-123",
				"--source-namespace", "src-ns",
			},
			expErr: `Required flag "target-namespace" not set`,
		},
		{
			name: "api error",
			cmd:  fullTestCmd,
			expReq: &cloudservice.StartMigrationRequest{
				Spec:             fullTestSpec,
				AsyncOperationId: "req-xyz",
			},
			mockResp: nil,
			mockErr:  errors.New("some start err"),
			expErr:   "some start err",
		},
		{
			name: "success",
			cmd:  fullTestCmd,
			expReq: &cloudservice.StartMigrationRequest{
				Spec:             fullTestSpec,
				AsyncOperationId: "req-xyz",
			},
			mockResp: &cloudservice.StartMigrationResponse{
				MigrationId:    "abc",
				AsyncOperation: &operation.AsyncOperation{Id: "req-xyz"},
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			if tc.expReq != nil {
				s.mockCloudApiClient.EXPECT().StartMigration(gomock.Any(), tc.expReq).
					Return(tc.mockResp, tc.mockErr).Times(1)
			}

			err := s.RunCmd(tc.cmd)
			if len(tc.expErr) != 0 {
				s.ErrorContains(err, tc.expErr)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *MigrationTestSuite) TestHandover() {
	testcases := []struct {
		name     string
		cmd      []string
		expReq   *cloudservice.HandoverNamespaceRequest
		mockResp *cloudservice.HandoverNamespaceResponse
		mockErr  error

		expErr string
	}{
		{
			name: "missing id",
			cmd: []string{
				"migration", "handover",
				"--to-replica-id", "cloud",
			},
			expErr: `Required flag "id" not set`,
		},
		{
			name: "missing to-replica-id",
			cmd: []string{
				"migration", "handover",
				"--id", "abc",
			},
			expErr: `Required flag "to-replica-id" not set`,
		},
		{
			name: "api error",
			cmd: []string{
				"migration", "handover",
				"--id", "abc",
				"--to-replica-id", "cloud",
			},
			expReq: &cloudservice.HandoverNamespaceRequest{
				MigrationId: "abc",
				ToReplicaId: "cloud",
			},
			mockErr: errors.New("some err"),
			expErr:  "some err",
		},
		{
			name: "success",
			cmd: []string{
				"migration", "handover",
				"--id", "abc",
				"--to-replica-id", "cloud",
				"--request-id", "req-xyz",
			},
			expReq: &cloudservice.HandoverNamespaceRequest{
				MigrationId:      "abc",
				ToReplicaId:      "cloud",
				AsyncOperationId: "req-xyz",
			},
			mockResp: &cloudservice.HandoverNamespaceResponse{
				AsyncOperation: &operation.AsyncOperation{Id: "req-xyz"},
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			if tc.expReq != nil {
				s.mockCloudApiClient.EXPECT().HandoverNamespace(gomock.Any(), tc.expReq).
					Return(tc.mockResp, tc.mockErr).Times(1)
			}

			err := s.RunCmd(tc.cmd)
			if len(tc.expErr) != 0 {
				s.ErrorContains(err, tc.expErr)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *MigrationTestSuite) TestConfirm() {
	testcases := []struct {
		name     string
		cmd      []string
		expReq   *cloudservice.ConfirmMigrationRequest
		mockResp *cloudservice.ConfirmMigrationResponse
		mockErr  error

		expErr string
	}{
		{
			name:   "missing id",
			cmd:    []string{"migration", "confirm"},
			expErr: `Required flag "id" not set`,
		},
		{
			name: "api error",
			cmd:  []string{"migration", "confirm", "--id", "abc"},
			expReq: &cloudservice.ConfirmMigrationRequest{
				MigrationId: "abc",
			},
			mockErr: errors.New("some err"),
			expErr:  "some err",
		},
		{
			name: "success",
			cmd: []string{
				"migration", "confirm",
				"--id", "abc",
				"--request-id", "req-xyz",
			},
			expReq: &cloudservice.ConfirmMigrationRequest{
				MigrationId:      "abc",
				AsyncOperationId: "req-xyz",
			},
			mockResp: &cloudservice.ConfirmMigrationResponse{
				AsyncOperation: &operation.AsyncOperation{Id: "req-xyz"},
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			if tc.expReq != nil {
				s.mockCloudApiClient.EXPECT().ConfirmMigration(gomock.Any(), tc.expReq).
					Return(tc.mockResp, tc.mockErr).Times(1)
			}

			err := s.RunCmd(tc.cmd)
			if len(tc.expErr) != 0 {
				s.ErrorContains(err, tc.expErr)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *MigrationTestSuite) TestAbort() {
	testcases := []struct {
		name     string
		cmd      []string
		expReq   *cloudservice.AbortMigrationRequest
		mockResp *cloudservice.AbortMigrationResponse
		mockErr  error

		expErr string
	}{
		{
			name:   "missing id",
			cmd:    []string{"migration", "abort"},
			expErr: `Required flag "id" not set`,
		},
		{
			name: "api error",
			cmd:  []string{"migration", "abort", "--id", "abc"},
			expReq: &cloudservice.AbortMigrationRequest{
				MigrationId: "abc",
			},
			mockErr: errors.New("some err"),
			expErr:  "some err",
		},
		{
			name: "success",
			cmd: []string{
				"migration", "abort",
				"--id", "abc",
				"--request-id", "req-xyz",
			},
			expReq: &cloudservice.AbortMigrationRequest{
				MigrationId:      "abc",
				AsyncOperationId: "req-xyz",
			},
			mockResp: &cloudservice.AbortMigrationResponse{
				AsyncOperation: &operation.AsyncOperation{Id: "req-xyz"},
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.name, func() {
			if tc.expReq != nil {
				s.mockCloudApiClient.EXPECT().AbortMigration(gomock.Any(), tc.expReq).
					Return(tc.mockResp, tc.mockErr).Times(1)
			}

			err := s.RunCmd(tc.cmd)
			if len(tc.expErr) != 0 {
				s.ErrorContains(err, tc.expErr)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *MigrationTestSuite) makeMigration(id string) *cloudNamespace.Migration {
	return &cloudNamespace.Migration{
		MigrationId: id,
		Spec: &cloudNamespace.MigrationSpec{
			MigrationEndpointId: "ep-123",
			Spec: &cloudNamespace.MigrationSpec_ToCloudSpec{
				ToCloudSpec: &cloudNamespace.MigrationToCloudSpec{
					SourceNamespace: "src-ns",
					TargetNamespace: "tgt-ns",
				},
			},
		},
		State: 2,
		Replicas: []*cloudNamespace.MigrationReplica{
			{Id: "on-prem", State: 1},
			{Id: "cloud", State: 2},
		},
	}
}
