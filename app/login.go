package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/temporalio/tcld/services"

	"github.com/urfave/cli/v2"
)

const (
	scope = "openid profile user"
)

var (
	tokenFileName = "tokens.json"
	domainFlag    = &cli.StringFlag{
		Name:     "domain",
		Value:    "login.tmprl.cloud",
		Aliases:  []string{"d"},
		Required: false,
		Hidden:   true,
	}
	audienceFlag = &cli.StringFlag{
		Name:     "audience",
		Value:    "https://saas-api.tmprl.cloud",
		Aliases:  []string{"a"},
		Required: false,
		Hidden:   true,
	}
	clientIDFlag = &cli.StringFlag{
		Name:     "client-id",
		Value:    "d7V5bZMLCbRLfRVpqC567AqjAERaWHhl",
		Aliases:  []string{"id"},
		Required: false,
		Hidden:   true,
	}
	disablePopUpFlag = &cli.BoolFlag{
		Name:     "disable-pop-up",
		Usage:    "disable browser pop-up",
		Required: false,
	}
)

func GetLoginClient() *LoginClient {
	return &LoginClient{
		loginService: services.NewLoginService(),
	}
}

type (
	LoginClient struct {
		loginService services.LoginService
	}

	OAuthDeviceCodeResponse struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}

	OAuthTokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
)

func getTokenConfigPath(ctx *cli.Context) string {
	configDir := ctx.Path(ConfigDirFlagName)
	return filepath.Join(configDir, tokenFileName)
}

// TODO: support login config on windows
func loadLoginConfig(ctx *cli.Context) (OAuthTokenResponse, error) {

	tokens := OAuthTokenResponse{}
	configDir := ctx.Path(ConfigDirFlagName)
	// Create config dir if it does not exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return tokens, err
	}

	tokenConfig := getTokenConfigPath(ctx)
	if _, err := os.Stat(tokenConfig); err != nil {
		// Skip if file does not exist
		if errors.Is(err, os.ErrNotExist) {
			return tokens, nil
		}
		return tokens, err
	}

	tokenConfigBytes, err := ioutil.ReadFile(tokenConfig)
	if err != nil {
		return tokens, err
	}

	if err := json.Unmarshal(tokenConfigBytes, &tokens); err != nil {
		return tokens, err
	}

	return tokens, nil
}

func parseURL(s string) (*url.URL, error) {
	// Without a scheme, url.Parse would interpret the path as a relative file path.
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = fmt.Sprintf("%s%s", "https://", s)
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return u, err
}

func (c *LoginClient) login(ctx *cli.Context, domain string, audience string, clientID string, disablePopUp bool) error {
	// Get device code
	domainURL, err := parseURL(domain)
	if err != nil {
		return err
	}

	codeResp := OAuthDeviceCodeResponse{}
	if err := postFormRequest(
		domainURL.JoinPath("oauth", "device", "code").String(),
		url.Values{
			"client_id": {clientID},
			"scope":     {scope},
			"audience":  {audience},
		},
		&codeResp,
	); err != nil {
		return err
	}

	verificationURL, err := parseURL(codeResp.VerificationURIComplete)
	if err != nil {
		return fmt.Errorf("failed to parse verification URL: %w", err)
	} else if verificationURL.Hostname() != domainURL.Hostname() {
		// We expect the verification URL to be the same host as the domain URL.
		// Otherwise the response could have us POST to any arbitrary URL.
		return fmt.Errorf("domain URL `%s` does not match verification URL `%s` in response", domainURL.Hostname(), verificationURL.Hostname())
	}

	fmt.Printf("Login via this url: %s\n", verificationURL.String())

	if !disablePopUp {
		if err := c.loginService.OpenBrowser(verificationURL.String()); err != nil {
			fmt.Println("Unable to open browser, please open url manually.")
		}
	}

	// According to RFC, we should set a default polling interval if not provided.
	// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-07#section-3.5
	if codeResp.Interval == 0 {
		codeResp.Interval = 10
	}

	// Get access token
	tokenResp := OAuthTokenResponse{}
	for len(tokenResp.AccessToken) == 0 {
		time.Sleep(time.Duration(codeResp.Interval) * time.Second)

		if err := postFormRequest(
			domainURL.JoinPath("oauth", "token").String(),
			url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"device_code": {codeResp.DeviceCode},
				"client_id":   {clientID},
			},
			&tokenResp,
		); err != nil {
			return err
		}
	}

	tokenRespJson, err := FormatJson(tokenResp)
	if err != nil {
		return err
	}
	fmt.Println("Successfully logged in!")

	// Save token info locally
	return c.loginService.WriteToConfigFile(getTokenConfigPath(ctx), tokenRespJson)
}

func NewLoginCommand(c *LoginClient) (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "login",
		Usage:   "Login as user",
		Aliases: []string{"l"},
		Before: func(ctx *cli.Context) error {
			// attempt to create and or load the login config at the beginning
			_, err := loadLoginConfig(ctx)
			return err
		},
		Flags: []cli.Flag{
			domainFlag,
			audienceFlag,
			clientIDFlag,
			disablePopUpFlag,
		},
		Action: func(ctx *cli.Context) error {
			return c.login(ctx, ctx.String("domain"), ctx.String("audience"), ctx.String("client-id"), ctx.Bool("disable-pop-up"))
		},
	}}, nil
}

func postFormRequest(url string, values url.Values, resStruct interface{}) error {
	res, err := http.PostForm(url, values)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, &resStruct)
}
