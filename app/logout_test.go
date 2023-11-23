package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

func TestLogout(t *testing.T) {
	suite.Run(t, new(LogoutTestSuite))
}

type LogoutTestSuite struct {
	suite.Suite

	cliApp    *cli.App
	server    *httptest.Server
	mux       *http.ServeMux
	configDir string
}

func (l *LogoutTestSuite) SetupTest() {
	l.mux = http.NewServeMux()

	l.server = httptest.NewServer(l.mux)

	out, err := NewLogoutCommand()
	l.Require().NoError(err)

	cmds := []*cli.Command{
		out.Command,
	}
	flags := []cli.Flag{
		ConfigDirFlag,
		disablePopUpFlag,
	}
	l.cliApp, l.configDir = NewTestApp(l.T(), cmds, flags)
}

func (l *LogoutTestSuite) TearDownTest() {
	l.server.Close()
}

func (l *LogoutTestSuite) runCmd(args ...string) error {
	return l.cliApp.Run(append([]string{"tcld"}, args...))
}

func (l *LogoutTestSuite) TestLogoutSuccessful() {
	loginConfig := LoginConfig{
		Config: oauth2.Config{
			ClientID:     "test-id",
			ClientSecret: "test-secret",
		},
		configDir: l.configDir,
	}

	err := loginConfig.StoreConfig()
	l.NoError(err)

	_, err = os.Stat(filepath.Join(l.configDir, tokenFile))
	l.NoError(err)

	resp := l.runCmd("logout", "--domain", l.server.URL)
	l.NoError(resp)

	_, err = os.Stat(filepath.Join(l.configDir, tokenFile))
	l.ErrorIs(err, os.ErrNotExist)
}
