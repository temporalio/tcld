package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/urfave/cli/v2"
)

var (
	tokenFile  = "tokens.json"
	domainFlag = &cli.StringFlag{
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

func NewLoginCommand() (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "login",
		Usage:   "Login as user",
		Aliases: []string{"l"},
		Flags: []cli.Flag{
			domainFlag,
			audienceFlag,
			clientIDFlag,
			disablePopUpFlag,
		},
		Action: func(ctx *cli.Context) error {
			return login(ctx, ctx.String("domain"), ctx.String("audience"), ctx.String("client-id"), ctx.Bool("disable-pop-up"))
		},
	}}, nil
}

type LoginConfig struct {
	Config      oauth2.Config `json:"config"`
	StoredToken oauth2.Token  `json:"token"`

	ctx       context.Context // used for token refreshes.
	configDir string
	isLegacy  bool
}

func NewLoginConfig(ctx context.Context, configDir string) (*LoginConfig, error) {
	// Create config dir if it does not exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, err
	}

	tokenConfig := filepath.Join(configDir, tokenFile)
	fileInfo, err := os.Stat(tokenConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to stat login config: %w", err)
	}

	data, err := os.ReadFile(tokenConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read login config: %w", err)
	}

	var config LoginConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login config: %w", err)
	} else if config.StoredToken == (oauth2.Token{}) {
		var legacy legacyOAuthToken

		err = json.Unmarshal(data, &legacy)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal legacy login config: %w", err)
		}

		config.StoredToken, err = legacy.convert(fileInfo.ModTime())
		if err != nil {
			return nil, fmt.Errorf("failed to convert legacy token: %w", err)
		}

		config.isLegacy = true
	}

	config.ctx = ctx
	config.configDir = configDir

	return &config, nil
}

func (c *LoginConfig) TokenSource() oauth2.TokenSource {
	if c == nil {
		return nil
	}

	return oauth2.ReuseTokenSource(nil, c)
}

func (c *LoginConfig) Token() (*oauth2.Token, error) {
	if c == nil {
		return nil, fmt.Errorf("nil token source")
	}

	grace := c.StoredToken.Expiry.Add(-1 * time.Minute)
	if c.isLegacy || c.StoredToken.Expiry.IsZero() || time.Now().Before(grace) {
		// Token has not expired, or is a legacy token, use it.
		return &c.StoredToken, nil
	}

	// Token has expired, refresh it.
	token, err := c.Config.TokenSource(c.ctx, &c.StoredToken).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh access token: %w", err)
	}

	c.StoredToken = *token
	c.StoreConfig()

	return token, nil
}

func (c *LoginConfig) StoreConfig() error {
	data, err := FormatJson(c)
	if err != nil {
		return fmt.Errorf("failed to format login config update: %w", err)
	}

	// Write file as 0600 because it contains private keys.
	return os.WriteFile(filepath.Join(c.configDir, tokenFile), []byte(data), 0600)
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

func login(ctx *cli.Context, domain string, audience string, clientID string, disablePopUp bool) error {
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
		if err := openBrowser(verificationURL.String()); err != nil {
			fmt.Println("Unable to open browser, please open url manually.")
		}
	}

	token, err := config.DeviceAccessToken(ctx.Context, resp)
	if err != nil {
		return fmt.Errorf("failed to retrieve access token: %w", err)
	}
	fmt.Println("Successfully logged in!")

	loginConfig := LoginConfig{
		Config:      config,
		StoredToken: *token,
		configDir:   ctx.Path(ConfigDirFlagName),
	}
	return loginConfig.StoreConfig()
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

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		if err := exec.Command("xdg-open", url).Start(); err != nil {
			return err
		}
	case "windows":
		if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start(); err != nil {
			return err
		}
	case "darwin":
		if err := exec.Command("open", url).Start(); err != nil {
			return err
		}
	default:
	}
	return nil
}

// legacyOAuthToken is the legacy token version, which is kept around to
// ensure a seamless updating experience from an older tcld version.
type legacyOAuthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func (l legacyOAuthToken) convert(modTime time.Time) (oauth2.Token, error) {
	return oauth2.Token{
		AccessToken:  l.AccessToken,
		TokenType:    l.TokenType,
		RefreshToken: l.RefreshToken,
		Expiry:       modTime.Add(time.Duration(l.ExpiresIn) * time.Second),
	}, nil
}
