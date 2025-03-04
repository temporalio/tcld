package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/app/credentials"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/operation/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	"github.com/temporalio/tcld/protogen/api/requestservice/v1"
	"github.com/urfave/cli/v2"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const (
	testAPIKey      = "testprefix_testid_testsecret"
	testAccessToken = "test-token"
)

type testServer struct {
	requestservice.UnimplementedRequestServiceServer
	cloudservice.UnimplementedCloudServiceServer

	receivedMD metadata.MD
}

func (s *testServer) GetRequestStatus(ctx context.Context, req *requestservice.GetRequestStatusRequest) (*requestservice.GetRequestStatusResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.receivedMD = md.Copy()

	return &requestservice.GetRequestStatusResponse{
		RequestStatus: &request.RequestStatus{
			RequestId: "test-request-id",
			State:     request.STATE_FULFILLED,
		},
	}, nil
}

func (s *testServer) GetAsyncOperation(ctx context.Context, req *cloudservice.GetAsyncOperationRequest) (*cloudservice.GetAsyncOperationResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.receivedMD = md.Copy()

	return &cloudservice.GetAsyncOperationResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id:    "test-id",
			State: operation.STATE_FULFILLED,
		},
	}, nil
}

type ServerConnectionTestSuite struct {
	suite.Suite
	listener    *bufconn.Listener
	grpcSrv     *grpc.Server
	testService *testServer
}

func TestServerConnection(t *testing.T) {
	suite.Run(t, new(ServerConnectionTestSuite))
}

func (s *ServerConnectionTestSuite) SetupTest() {
	s.listener = bufconn.Listen(1024 * 1024)
	s.grpcSrv = grpc.NewServer()
	s.testService = &testServer{}

	requestservice.RegisterRequestServiceServer(s.grpcSrv, s.testService)
	cloudservice.RegisterCloudServiceServer(s.grpcSrv, s.testService)

	go func() {
		err := s.grpcSrv.Serve(s.listener)
		require.NoError(s.T(), err)
	}()
}

func (s *ServerConnectionTestSuite) TeardownTest() {
	s.grpcSrv.Stop()
	s.listener.Close()
}

func (s *ServerConnectionTestSuite) SetupSubtest() {
	s.SetupTest()
}

func (s *ServerConnectionTestSuite) TeardownSubtest() {
	s.TeardownTest()
}

func (s *ServerConnectionTestSuite) assertMetadata(apiVersion, token string) {
	md := s.testService.receivedMD
	buildInfo := NewBuildInfo()
	version := getHeaderValue(md, VersionHeader)
	s.Equal(buildInfo.Version, version)

	commit := getHeaderValue(md, CommitHeader)
	s.Equal(buildInfo.Commit, commit)

	v := getHeaderValue(md, TemporalCloudAPIVersionHeader)
	s.Equal(apiVersion, v)

	auth := strings.SplitN(getHeaderValue(md, credentials.AuthorizationHeader), " ", 2)
	require.Len(s.T(), auth, 2)

	s.Equal(strings.ToLower(credentials.AuthorizationBearer), strings.ToLower(auth[0]))
	s.Equal(token, auth[1])
}

func (s *ServerConnectionTestSuite) TestGetServerConnection() {
	testcases := []struct {
		name          string
		args          map[string]string
		expectedToken string
		expectedErr   error
	}{
		{
			name: "ErrorInvalidHostname",
			args: map[string]string{
				ServerFlagName: "localhost%%0",
			},
			expectedErr: fmt.Errorf("unable to parse server address"),
		},
		{
			name: "ErrorOAuthInsecureConnection",
			args: map[string]string{
				// don't include insecure flag, as this is an accidental insecure connection.
			},
			expectedErr: fmt.Errorf("the credentials require transport level security"),
		},
		{
			name: "ErrorAPIKeyInsecureConnection",
			args: map[string]string{
				APIKeyFlagName: testAPIKey,
				// don't include insecure flag, as this is an accidental insecure connection.
			},
			expectedErr: fmt.Errorf("the credentials require transport level security"),
		},
		{
			name: "OAuthSuccess",
			args: map[string]string{
				InsecureConnectionFlagName: "true", // required for bufconn
			},
			expectedToken: testAccessToken,
		},
		{
			name: "APIKeySuccess",
			args: map[string]string{
				InsecureConnectionFlagName: "true", // required for bufconn
				APIKeyFlagName:             testAPIKey,
			},
			expectedToken: testAPIKey,
		},
	}
	for _, tc := range testcases {
		s.Run(tc.name, func() {
			// setting the env var unexpectedly interferes with the test.
			require.NoError(s.T(), os.Unsetenv("TEMPORAL_CLOUD_API_KEY"))

			app, cfgDir := NewTestApp(s.T(), nil, []cli.Flag{
				ServerFlag,
				ConfigDirFlag,
				APIKeyFlag,
				InsecureConnectionFlag,
			})
			cCtx := NewTestContext(s.T(), app)

			require.NoError(s.T(), cCtx.Set(ServerFlagName, "bufnet"))
			require.NoError(s.T(), cCtx.Set(ConfigDirFlagName, cfgDir))
			for k, v := range tc.args {
				require.NoError(s.T(), cCtx.Set(k, v), "failed to parse flag %q set to %q", k, v)
			}

			loginConfig := TokenConfig{
				OAuthToken: &oauth2.Token{
					AccessToken: testAccessToken,
					Expiry:      time.Now().Add(24 * time.Hour),
				},
				ctx: cCtx,
			}

			err := loginConfig.Store()
			require.NoError(s.T(), err)

			opts := []grpc.DialOption{
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return s.listener.Dial()
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			}
			connCtx, conn, err := GetServerConnection(cCtx, opts...)
			if tc.expectedErr != nil {
				require.ErrorContains(s.T(), err, tc.expectedErr.Error())
				return // fin test.
			}
			require.NoError(s.T(), err)
			defer conn.Close()

			client := requestservice.NewRequestServiceClient(conn)
			_, err = client.GetRequestStatus(connCtx, &requestservice.GetRequestStatusRequest{
				RequestId: "test-request-id",
			})
			s.NoError(err)
			s.assertMetadata(LegacyTemporalCloudAPIVersion, tc.expectedToken)

			cloudClient := cloudservice.NewCloudServiceClient(conn)
			_, err = cloudClient.GetAsyncOperation(connCtx, &cloudservice.GetAsyncOperationRequest{
				AsyncOperationId: "test-async-operation-id",
			})
			s.NoError(err)
			s.assertMetadata(TemporalCloudAPIVersion, tc.expectedToken)
		})
	}
}

func getHeaderValue(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}
