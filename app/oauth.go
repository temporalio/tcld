package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

const (
	// OAuth error defined in RFC-6749.
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	invalidGrantErr = "invalid_grant"
)

func login(ctx *cli.Context) (*TokenConfig, error) {
	domainURL, err := parseURL(ctx.String(domainFlagName))
	if err != nil {
		return nil, fmt.Errorf("failed to parse domain: %w", err)
	}

	config := oauth2.Config{
		ClientID: ctx.String("client-id"),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: domainURL.JoinPath("oauth", "device", "code").String(),
			TokenURL:      domainURL.JoinPath("oauth", "token").String(),
			AuthStyle:     oauth2.AuthStyleInParams,
		},
		Scopes: []string{"openid", "profile", "user", "offline_access"},
	}

	resp, err := config.DeviceAuth(ctx.Context, oauth2.SetAuthURLParam("audience", ctx.String(audienceFlagName)))
	if err != nil {
		return nil, fmt.Errorf("failed to perform device auth: %w", err)
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

	token, err := config.DeviceAccessToken(ctx.Context, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve access token: %w", err)
	}
	// Print to stderr so other tooling can parse the command output.
	fmt.Fprintln(os.Stderr, "Successfully logged in!")

	tokenConfig := &TokenConfig{
		OAuthConfig: config,
		OAuthToken:  *token,
		ctx:         ctx,
	}

	err = tokenConfig.Store()
	if err != nil {
		return nil, fmt.Errorf("failed to store token config: %w", err)
	}

	return tokenConfig, nil
}

func ensureLogin(ctx *cli.Context) (*TokenConfig, error) {
	cfg, err := LoadTokenConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load token config: %w", err)
	}

	_, err = cfg.Token()
	if err != nil {
		var retrieveErr *oauth2.RetrieveError

		// Handle one of two cases:
		//   1. Refresh token has expired.
		//   2. Refresh tokens were enabled, but the user has not logged in to receive one yet.
		if (errors.As(err, &retrieveErr) && retrieveErr.ErrorCode == invalidGrantErr) ||
			len(cfg.OAuthToken.RefreshToken) == 0 {
			// Only attempt a forced login if used in an interactive terminal.
			if term.IsTerminal(int(os.Stdout.Fd())) {
				cfg, err = login(ctx)
				if err != nil {
					return nil, fmt.Errorf("failed to login: %w", err)
				}

				_, err := cfg.Token()
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve auth token: %w", err)
				}

				err = cfg.Store()
				if err != nil {
					return nil, fmt.Errorf("failed to store new tokens: %w", err)
				}

				return cfg, nil
			}
		}

		return nil, err
	}

	return cfg, nil
}
