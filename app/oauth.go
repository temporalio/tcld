package app

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

const (
	// OAuth error defined in RFC-6749.
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	invalidGrantErr = "invalid_grant"
)

func login(ctx *cli.Context, tokenConfig *TokenConfig) (*TokenConfig, error) {
	if tokenConfig == nil {
		defaultConfig, err := defaultTokenConfig(ctx)
		if err != nil {
			return nil, err
		}
		tokenConfig = defaultConfig
	}

	resp, err := tokenConfig.OAuthConfig.DeviceAuth(ctx.Context, oauth2.SetAuthURLParam("audience", tokenConfig.Audience))
	if err != nil {
		return nil, fmt.Errorf("failed to perform device auth: %w", err)
	}

	domainURL, err := parseURL(tokenConfig.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse domain: %w", err)
	}

	verificationURL, err := parseURL(resp.VerificationURIComplete)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verification URL: %w", err)
	} else if verificationURL.Hostname() != domainURL.Hostname() {
		// We expect the verification URL to be the same host as the domain URL.
		// Otherwise the response could have us POST to any arbitrary URL.
		return nil, fmt.Errorf("domain URL `%s` does not match verification URL `%s` in response", domainURL.Hostname(), verificationURL.Hostname())
	}

	err = openBrowser(ctx, "Login via this url", verificationURL.String())
	if err != nil {
		// Notify the user but ensure they can continue the process.
		fmt.Printf("Failed to open the browser, click the link to continue: %v", err)
	}

	token, err := tokenConfig.OAuthConfig.DeviceAccessToken(ctx.Context, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve access token: %w", err)
	}
	// Print to stderr so other tooling can parse the command output.
	fmt.Fprintln(os.Stderr, "Successfully logged in!")

	tokenConfig.OAuthToken = token
	tokenConfig.ctx = ctx

	err = tokenConfig.Store()
	if err != nil {
		return nil, fmt.Errorf("failed to store token config: %w", err)
	}

	return tokenConfig, nil
}

func defaultTokenConfig(ctx *cli.Context) (*TokenConfig, error) {
	domainURL, err := parseURL(ctx.String(domainFlagName))
	if err != nil {
		return nil, fmt.Errorf("failed to parse domain URL: %w", err)
	}

	return &TokenConfig{
		Audience: ctx.String(audienceFlagName),
		Domain:   domainURL.String(),
		OAuthConfig: oauth2.Config{
			ClientID: ctx.String("client-id"),
			Endpoint: oauth2.Endpoint{
				DeviceAuthURL: domainURL.JoinPath("oauth", "device", "code").String(),
				TokenURL:      domainURL.JoinPath("oauth", "token").String(),
				AuthStyle:     oauth2.AuthStyleInParams,
			},
			Scopes: []string{"openid", "profile", "user", "offline_access"},
		},
		ctx: ctx,
	}, nil
}
