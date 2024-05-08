package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

const (
	tokenConfigFile = "tokens.json"
)

type TokenConfig struct {
	Audience    string        `json:"audience"`
	Domain      string        `json:"domain"`
	OAuthConfig oauth2.Config `json:"oauth_config"`
	OAuthToken  *oauth2.Token `json:"oauth_token"`

	ctx *cli.Context // used for token refreshes.
}

func LoadTokenConfig(ctx *cli.Context) (*TokenConfig, error) {
	tokenConfig := filepath.Join(ctx.String(ConfigDirFlagName), tokenConfigFile)

	_, err := os.Stat(tokenConfig)
	if err != nil {
		if os.IsNotExist(err) {
			cfg, err := login(ctx, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to login: %w", err)
			}

			return cfg, nil
		}

		return nil, fmt.Errorf("failed to stat login config: %w", err)
	}

	data, err := os.ReadFile(tokenConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read login config: %w", err)
	}

	var config *TokenConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login config: %w", err)
	} else if config.OAuthToken == nil {
		// Using legacy token format, ask user to initiate a login to migrate.
		fmt.Println("Re-login with `tcld login` to migrate to the new config format")
		os.Exit(1)
	}

	config.ctx = ctx // used for token refreshes.

	return config, nil
}

func (c *TokenConfig) TokenSource() oauth2.TokenSource {
	if c == nil {
		return nil
	}

	return oauth2.ReuseTokenSource(nil, c)
}

func (c *TokenConfig) Token() (*oauth2.Token, error) {
	if c == nil {
		return nil, fmt.Errorf("nil token source")
	}

	grace := c.OAuthToken.Expiry.Add(-1 * time.Minute)
	if c.OAuthToken.Expiry.IsZero() || time.Now().Before(grace) {
		// Token has not expired, or is a legacy token, use it.
		return c.OAuthToken, nil
	}

	// Token has expired, refresh it.
	token, err := c.OAuthConfig.TokenSource(c.ctx.Context, c.OAuthToken).Token()
	if err != nil {
		var retrieveErr *oauth2.RetrieveError

		// Handle one of two cases:
		//   1. Refresh token has expired.
		//   2. Refresh tokens were enabled, but the user has not logged in to receive one yet.
		if (errors.As(err, &retrieveErr) && retrieveErr.ErrorCode == invalidGrantErr) ||
			len(c.OAuthToken.RefreshToken) == 0 {
			cfg, err := login(c.ctx, c)
			if err != nil {
				return nil, fmt.Errorf("failed to login to retrieve new refresh token: %w", err)
			}

			token, err = cfg.OAuthConfig.TokenSource(cfg.ctx.Context, cfg.OAuthToken).Token()
			if err != nil {
				return nil, fmt.Errorf("failed to refresh access token after login: %w", err)
			}

			// Make sure the current config reflects the new config.
			c.OAuthConfig = cfg.OAuthConfig
			c.OAuthToken = token

			// Store the new config for the next CLI invocation.
			err = cfg.Store()
			if err != nil {
				return nil, fmt.Errorf("failed to store new refresh and access tokens: %w", err)
			}

			return token, nil
		}

		return nil, fmt.Errorf("failed to refresh access token: %w", err)
	}

	c.OAuthToken = token
	err = c.Store()
	if err != nil {
		return nil, fmt.Errorf("failed to store refreshed token: %w", err)
	}

	return token, nil
}

func (c *TokenConfig) Store() error {
	cfgDir := c.ctx.String(ConfigDirFlagName)

	data, err := FormatJson(c)
	if err != nil {
		return fmt.Errorf("failed to format login config update: %w", err)
	}

	// Create config dir if it does not exist
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return err
	}

	// Write file as 0600 because it contains private keys.
	return os.WriteFile(filepath.Join(cfgDir, tokenConfigFile), []byte(data), 0600)
}
