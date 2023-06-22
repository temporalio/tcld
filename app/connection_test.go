package app

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc/metadata"
)

func TestServerConnection(t *testing.T) {
	suite.Run(t, new(ServerConnectionTestSuite))
}

type ServerConnectionTestSuite struct {
	suite.Suite
	mockCtrl *gomock.Controller
}

func (s *ServerConnectionTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
}

func (s *ServerConnectionTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *ServerConnectionTestSuite) TestServerName() {

	testConfDir := "testconfig"
	testHostname := "saas-api.tmprl.cloud:443"
	testToken := "some-testing-token"
	tests := []struct {
		name      string
		hostname  string
		configDir string
		token     string
		expectErr bool
	}{{
		name:      "invalid hostname",
		hostname:  "invalidhostname",
		expectErr: true,
	}, {
		name:      "success",
		hostname:  testHostname,
		configDir: testConfDir,
	}}
	for _, tc := range tests {
		s.Run(tc.name, func() {

			err := os.MkdirAll(testConfDir, 0755)
			s.Require().NoError(err)
			defer os.RemoveAll(testConfDir)

			data, err := json.Marshal(OAuthTokenResponse{
				AccessToken: testToken,
			})
			s.Require().NoError(err)
			err = ioutil.WriteFile(path.Join(testConfDir, tokenFileName), data, 0644)
			s.Require().NoError(err)

			cmd := cli.Command{
				Name: "test",
				Before: func(ctx *cli.Context) error {
					c, conn, err := GetServerConnection(ctx)
					if tc.expectErr {
						s.Error(err)
						return nil
					}
					s.NoError(err)
					s.NotNil(c)
					md, ok := metadata.FromOutgoingContext(c)
					s.True(ok)
					s.Contains(md["authorization"], "Bearer "+testToken)

					s.NotNil(conn)
					s.Equal(conn.Target(), testHostname)
					return nil
				},
			}
			cliApp := &cli.App{
				Name:     "test",
				Commands: []*cli.Command{&cmd},
				Flags: []cli.Flag{
					ServerFlag,
					ConfigDirFlag,
				},
			}
			err = cliApp.Run([]string{"tcld", "-s", tc.hostname, "--config-dir", testConfDir, "test"})
			s.NoError(err)
		})
	}
}
