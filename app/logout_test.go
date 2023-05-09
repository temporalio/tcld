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

func TestLogout(t *testing.T) {
	suite.Run(t, new(LogoutTestSuite))
}

type LogoutTestSuite struct {
	suite.Suite
	cliApp      *cli.App
	server      *httptest.Server
	mux         *http.ServeMux
	mockCtrl    *gomock.Controller
	mockService *services.MockLoginService
}

func (l *LogoutTestSuite) SetupTest() {
	l.mockCtrl = gomock.NewController(l.T())
	l.mockService = services.NewMockLoginService(l.mockCtrl)
	l.mux = http.NewServeMux()
	l.server = httptest.NewServer(l.mux)
	out, err := NewLogoutCommand(&LoginClient{
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

func (l *LogoutTestSuite) runCmd(args ...string) error {
	return l.cliApp.Run(append([]string{"tcld"}, args...))
}

func (l *LogoutTestSuite) TestLogoutSuccessful() {
	l.mockService.EXPECT().DeleteConfigFile(gomock.Any()).Return(nil)
	l.mockService.EXPECT().OpenBrowser(gomock.Any()).Return(nil)
	resp := l.runCmd("logout", "--domain", l.server.URL)
	l.NoError(resp)
}

func (l *LogoutTestSuite) TestLogoutDisablePopup() {
	l.mockService.EXPECT().DeleteConfigFile(gomock.Any()).Return(nil)
	resp := l.runCmd("logout", "--domain", l.server.URL, "--disable-pop-up")
	l.NoError(resp)
}

func (l *LogoutTestSuite) AfterTest(_, _ string) {
	l.mockCtrl.Finish()
	l.server.Close()
}
