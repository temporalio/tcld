package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/services"
	"github.com/urfave/cli/v2"
)

var validOauthDeviceCodeResponse = `{
	"device_code": "ABCD-EFGH",
	"user_code": "ABCD-EFGH",
	"verification_uri": "verification/uri",
	"verification_uri_complete": "",
	"interval": 0,
	"expires_in": 0
}`

var validOauthTokenResponse = `{
	"access_token": "EabWErgdh",
	"refresh_token": "eWKjhgT",
	"id_token": "iJktYuVk",
	"token_type": "Bearer",
	"expires_in": 1234
}`

func TestLogin(t *testing.T) {
	suite.Run(t, new(LoginTestSuite))
}

type LoginTestSuite struct {
	suite.Suite
	cliApp      *cli.App
	server      *httptest.Server
	mux         *http.ServeMux
	mockCtrl    *gomock.Controller
	mockService *services.MockLoginService
}

func (l *LoginTestSuite) SetupTest() {
	l.mockCtrl = gomock.NewController(l.T())
	l.mockService = services.NewMockLoginService(l.mockCtrl)
	l.mux = http.NewServeMux()
	l.server = httptest.NewServer(l.mux)
	out, err := NewLoginCommand(&LoginClient{
		loginService: l.mockService,
	})
	l.Require().NoError(err)
	l.cliApp = &cli.App{
		Name:     "test",
		Commands: []*cli.Command{out.Command},
		Flags: []cli.Flag{
			ConfigDirFlag,
		},
	}
}

func (l *LoginTestSuite) registerPath(path string, response string) {
	l.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(response))
		if err != nil {
			return
		}
	})
}

func (l *LoginTestSuite) runCmd(args ...string) error {
	return l.cliApp.Run(append([]string{"tcld"}, args...))
}

func (l *LoginTestSuite) TestLoginSuccessful() {
	l.mockService.EXPECT().OpenBrowser(gomock.Any()).Return(nil)
	l.mockService.EXPECT().WriteToConfigFile(gomock.Any(), gomock.Any()).Return(nil)
	l.registerPath("/oauth/device/code", validOauthDeviceCodeResponse)
	l.registerPath("/oauth/token", validOauthTokenResponse)
	resp := l.runCmd("login", "--domain", l.server.URL)
	l.NoError(resp)
}

func (l *LoginTestSuite) TestLoginFailureAtDeviceVerification() {
	l.registerPath("/oauth/device/code", ``)
	l.Error(l.runCmd("login", "--domain", l.server.URL))
}

func (l *LoginTestSuite) TestLoginFailureAtTokenResponse() {
	l.mockService.EXPECT().OpenBrowser(gomock.Any()).Return(nil)
	l.registerPath("/oauth/device/code", validOauthDeviceCodeResponse)
	l.registerPath("/oauth/token", ``)
	l.Error(l.runCmd("login", "--domain", l.server.URL))
}

func (l *LoginTestSuite) TestLoginWithInvalidDomain() {
	l.registerPath("/oauth/device/code", validOauthDeviceCodeResponse)
	l.registerPath("/oauth/token", validOauthTokenResponse)
	l.Error(l.runCmd("login", "--domain", "test"))
}

func (l *LoginTestSuite) AfterTest(_, _ string) {
	l.mockCtrl.Finish()
	l.server.Close()
}
