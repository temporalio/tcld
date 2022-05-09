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

	OauthDeviceCodeResponse struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}

	OauthTokenResponse struct {
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
func loadLoginConfig(ctx *cli.Context) (OauthTokenResponse, error) {

	tokens := OauthTokenResponse{}
	configDir := ctx.Path(ConfigDirFlagName)
	// Create config dir if it does not exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
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

func getURLFromDomain(domain string) (string, error) {
	u, err := url.Parse(domain)
	if err != nil {
		return domain, err
	}
	if u.Scheme == "" {
		return fmt.Sprintf("https://%s", domain), nil
	}
	return domain, nil
}

func (c *LoginClient) login(ctx *cli.Context, domain string, audience string, clientID string) error {
	// Get device code
	oauthDeviceCodeResponse := OauthDeviceCodeResponse{}
	domain, err := getURLFromDomain(domain)
	if err != nil {
		return err
	}
	if err := postRequest(
		fmt.Sprintf("%s/oauth/device/code", domain),
		fmt.Sprintf("client_id=%s&scope=%s&audience=%s", clientID, scope, audience),
		&oauthDeviceCodeResponse,
	); err != nil {
		return err
	}

	fmt.Printf("Login via this url: %s\n", oauthDeviceCodeResponse.VerificationURIComplete)

	if err := c.loginService.OpenBrowser(oauthDeviceCodeResponse.VerificationURIComplete); err != nil {
		fmt.Println("Unable to open browser, please open url manually.")
	}

	// Get access token
	oauthTokenResponse := OauthTokenResponse{}
	for len(oauthTokenResponse.AccessToken) == 0 {
		time.Sleep(time.Duration(oauthDeviceCodeResponse.Interval) * time.Second)

		if err := postRequest(
			fmt.Sprintf("%s/oauth/token", domain),
			fmt.Sprintf(
				"grant_type=%s&device_code=%s&client_id=%s",
				"urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
				oauthDeviceCodeResponse.DeviceCode,
				clientID,
			),
			&oauthTokenResponse,
		); err != nil {
			return err
		}
	}

	oauthTokenResponseJson, err := FormatJson(oauthTokenResponse)
	if err != nil {
		return err
	}
	fmt.Println("Successfully logged in!")

	// Save token info locally
	return c.loginService.WriteToConfigFile(getTokenConfigPath(ctx), oauthTokenResponseJson)
}

func NewLoginCommand(c *LoginClient) (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "login",
		Usage:   "login as user",
		Aliases: []string{"l"},
		Before: func(ctx *cli.Context) error {
			// attempt to create and or load the login config at the beginning
			_, err := loadLoginConfig(ctx)
			return err
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "domain",
				Value:    "login.tmprl.cloud",
				Aliases:  []string{"d"},
				Required: false,
				Hidden:   true,
			},
			&cli.StringFlag{
				Name:     "audience",
				Value:    "https://saas-api.tmprl.cloud",
				Aliases:  []string{"a"},
				Required: false,
				Hidden:   true,
			},
			&cli.StringFlag{
				Name:     "client-id",
				Value:    "d7V5bZMLCbRLfRVpqC567AqjAERaWHhl",
				Aliases:  []string{"id"},
				Required: false,
				Hidden:   true,
			},
		},
		Action: func(ctx *cli.Context) error {
			return c.login(ctx, ctx.String("domain"), ctx.String("audience"), ctx.String("client-id"))
		},
	}}, nil
}

func postRequest(url string, formData string, resStruct interface{}) error {
	payload := strings.NewReader(formData)
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return err
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
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
