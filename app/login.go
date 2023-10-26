package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/temporalio/tcld/services"
	"golang.org/x/oauth2"

	"github.com/urfave/cli/v2"
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
)

func getTokenConfigPath(ctx *cli.Context) string {
	configDir := ctx.Path(ConfigDirFlagName)
	return filepath.Join(configDir, tokenFileName)
}

// TODO: support login config on windows
func loadLoginConfig(ctx *cli.Context) (oauth2.TokenSource, error) {
	configDir := ctx.Path(ConfigDirFlagName)
	// Create config dir if it does not exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, err
	}

	tokenConfig := getTokenConfigPath(ctx)
	if _, err := os.Stat(tokenConfig); err != nil {
		// Skip if file does not exist
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	tokenConfigBytes, err := os.ReadFile(tokenConfig)
	if err != nil {
		return nil, err
	}

	var token oauth2.Token
	if err := json.Unmarshal(tokenConfigBytes, &token); err != nil {
		return nil, err
	}

	oauthConfig, err := oauthConfig(ctx)
	if err != nil {
		return nil, err
	}

	return oauthConfig.TokenSource(ctx.Context, &token), nil
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
	config, err := oauthConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve oauth2 config: %w", err)
	}

	resp, err := config.DeviceAuth(ctx.Context, oauth2.SetAuthURLParam("audience", audience))
	if err != nil {
		return fmt.Errorf("failed to perform device auth: %w", err)
	}

	domainURL, err := parseURL(ctx.String("domain"))
	if err != nil {
		return err
	}

	verificationURL, err := parseURL(resp.VerificationURIComplete)
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

	token, err := config.DeviceAccessToken(ctx.Context, resp)
	if err != nil {
		return fmt.Errorf("failed to retrieve access token: %w", err)
	}
	fmt.Println("Successfully logged in!")

	tokenRespJson, err := FormatJson(token)
	if err != nil {
		return err
	}

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

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, &resStruct)
}

func oauthConfig(ctx *cli.Context) (oauth2.Config, error) {
	domainURL, err := parseURL(ctx.String("domain"))
	if err != nil {
		return oauth2.Config{}, err
	}

	return oauth2.Config{
		ClientID: ctx.String("client-id"),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: domainURL.JoinPath("oauth", "device", "code").String(),
			TokenURL:      domainURL.JoinPath("oauth", "token").String(),
			AuthStyle:     oauth2.AuthStyleInParams,
		},
		Scopes: []string{"openid", "profile", "user", "offline_access"},
	}, nil
}
