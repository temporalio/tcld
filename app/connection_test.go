package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/app/credentials/apikey"
	"github.com/temporalio/tcld/app/credentials/oauth"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	"github.com/temporalio/tcld/protogen/api/requestservice/v1"
	"github.com/urfave/cli/v2"

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

type ServerConnectionTestSuite struct {
	suite.Suite
	configDir   string
	listener    *bufconn.Listener
	grpcSrv     *grpc.Server
	testService *testServer
}

func TestServerConnection(t *testing.T) {
	suite.Run(t, new(ServerConnectionTestSuite))
}

func (s *ServerConnectionTestSuite) SetupTest() {
	s.configDir = s.T().TempDir()
	data, err := json.Marshal(OAuthTokenResponse{
		AccessToken: testAccessToken,
	})
	require.NoError(s.T(), err)

	err = ioutil.WriteFile(path.Join(s.configDir, tokenFileName), data, 0600)
	require.NoError(s.T(), err)

	s.listener = bufconn.Listen(1024 * 1024)
	s.grpcSrv = grpc.NewServer()
	s.testService = &testServer{}
	requestservice.RegisterRequestServiceServer(s.grpcSrv, s.testService)
	go func() {
		err := s.grpcSrv.Serve(s.listener)
		require.NoError(s.T(), err)
	}()
}

func (s *ServerConnectionTestSuite) TeardownTest() {
	s.grpcSrv.Stop()
	s.listener.Close()
}

func (s *ServerConnectionTestSuite) TestGetServerConnection() {
	testcases := []struct {
		name            string
		args            map[string]string
		expectedHeaders map[string]string
		expectedErr     error
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
			name: "OAuthSucess",
			args: map[string]string{
				InsecureConnectionFlagName: "", // required for bufconn
			},
			expectedHeaders: map[string]string{
				oauth.Header: "Bearer " + testAccessToken,
			},
		},
		{
			name: "APIKeySucess",
			args: map[string]string{
				InsecureConnectionFlagName: "", // required for bufconn
				APIKeyFlagName:             testAPIKey,
			},
			expectedHeaders: map[string]string{
				apikey.AuthorizationHeader: "Bearer " + testAPIKey,
			},
		},
	}
	for _, tc := range testcases {
		s.Run(tc.name, func() {
			fs := flag.NewFlagSet(tc.name, flag.ContinueOnError)

			flags := []cli.Flag{
				ServerFlag,
				ConfigDirFlag,
				APIKeyFlag,
				InsecureConnectionFlag,
			}
			for _, f := range flags {
				require.NoError(s.T(), f.Apply(fs))
			}
			fs.SetOutput(io.Discard)

			cCtx := cli.NewContext(nil, fs, nil)
			args := []string{
				"--" + ConfigDirFlagName, s.configDir,
				"--" + ServerFlagName, "bufnet",
			}
			for k, v := range tc.args {
				args = append(args, "--"+k)
				if len(v) > 0 {
					args = append(args, v)
				}
			}
			require.NoError(s.T(), fs.Parse(args))

			opts := []grpc.DialOption{
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return s.listener.Dial()
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
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
			md := s.testService.receivedMD

			version := getHeaderValue(md, VersionHeader)
			s.Equal(getVersion(), version)

			commit := getHeaderValue(md, CommitHeader)
			s.Equal(Commit, commit)

			_, usingAPIKeys := tc.args[APIKeyFlagName]
			if usingAPIKeys {
				authHeader := getHeaderValue(md, apikey.AuthorizationHeader)
				s.Equal("Bearer "+testAPIKey, authHeader)
			} else {
				token := getHeaderValue(md, oauth.Header)
				s.Equal("Bearer "+testAccessToken, token)
			}
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
