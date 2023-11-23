package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

func TestLogin(t *testing.T) {
	suite.Run(t, new(LoginTestSuite))
}

type LoginTestSuite struct {
	suite.Suite

	token      oauth2.Token
	deviceAuth oauth2.DeviceAuthResponse

	cliApp    *cli.App
	server    *httptest.Server
	mux       *http.ServeMux
	configDir string
}

func (l *LoginTestSuite) SetupTest() {
	l.mux = http.NewServeMux()
	l.mux.Handle("/oauth/device/code", l.handleDeviceCode())
	l.mux.Handle("/oauth/token", l.handleToken())

	l.server = httptest.NewServer(l.mux)

	l.token = oauth2.Token{
		AccessToken:  "EabWErgdh",
		RefreshToken: "eWKjhgT",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(24 * time.Hour),
	}
	l.deviceAuth = oauth2.DeviceAuthResponse{
		DeviceCode:              "ABCD-EFGH",
		UserCode:                "ABCD-EFGH",
		Expiry:                  time.Now().Add(24 * time.Hour),
		Interval:                1,
		VerificationURI:         l.server.URL,
		VerificationURIComplete: l.server.URL,
	}

	out, err := NewLoginCommand()
	l.Require().NoError(err)

	cmds := []*cli.Command{
		out.Command,
	}
	flags := []cli.Flag{
		ConfigDirFlag,
		domainFlag,
		audienceFlag,
		clientIDFlag,
		disablePopUpFlag,
	}
	l.cliApp, l.configDir = NewTestApp(l.T(), cmds, flags)
}

func (l *LoginTestSuite) TearDownTest() {
	l.server.Close()
}

func (l *LoginTestSuite) TestLoginSuccessful() {
	resp := l.runCmd("login", "--domain", l.server.URL)
	l.NoError(resp)

	config, err := NewLoginConfig(context.Background(), l.configDir)
	l.NoError(err)
	l.Equal(l.token.AccessToken, config.StoredToken.AccessToken)
	l.Equal(l.token.RefreshToken, config.StoredToken.RefreshToken)
}

func (l *LoginTestSuite) TestLoginFailureAtDeviceVerification() {
	l.deviceAuth = oauth2.DeviceAuthResponse{}
	l.Error(l.runCmd("login", "--domain", l.server.URL))
}

func (l *LoginTestSuite) TestLoginFailureAtTokenResponse() {
	l.token = oauth2.Token{}
	l.Error(l.runCmd("login", "--domain", l.server.URL))
}

func (l *LoginTestSuite) TestLoginWithInvalidDomain() {
	l.Error(l.runCmd("login", "--domain", "test"))
}

func (l *LoginTestSuite) TestLoginWithInvalidCodeResponseURL() {
	l.deviceAuth.VerificationURI = "https://temporal.io"
	l.deviceAuth.VerificationURIComplete = "https://temporal.io"

	l.Error(l.runCmd("login", "--domain", l.server.URL))
}

func (l *LoginTestSuite) handleDeviceCode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		err := json.NewEncoder(w).Encode(l.deviceAuth)
		if err != nil {
			writeError(w, fmt.Errorf("failed to write token: %w", err))
			return
		}
	}
}

func (l *LoginTestSuite) handleToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		err := json.NewEncoder(w).Encode(l.token)
		if err != nil {
			writeError(w, fmt.Errorf("failed to write token: %w", err))
			return
		}
	}
}

func (l *LoginTestSuite) runCmd(args ...string) error {
	return l.cliApp.Run(append([]string{"tcld"}, args...))
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
