package app

import (
	"encoding/json"
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

var (
	unauthenticatedErr = fmt.Errorf("must authenticate by running `tcld login`")
)

type TokenConfig struct {
	Audience    string        `json:"audience"`
	Domain      string        `json:"domain"`
	OAuthConfig oauth2.Config `json:"oauth_config"`
	OAuthToken  oauth2.Token  `json:"oauth_token"`

	ctx *cli.Context // used for token refreshes.
}

func LoadTokenConfig(ctx *cli.Context) (*TokenConfig, error) {
	tokenConfig := filepath.Join(ctx.String(ConfigDirFlagName), tokenConfigFile)

	_, err := os.Stat(tokenConfig)
	if err != nil {
		// Only attempt a forced login if used in an interactive terminal.
		if os.IsNotExist(err) {
			return nil, unauthenticatedErr
		}

		return nil, err
	}

	data, err := os.ReadFile(tokenConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read login config: %w", err)
	}

	var config *TokenConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login config: %w", err)
	} else if config.OAuthToken == (oauth2.Token{}) {
		// Using legacy token format, ask user to initiate a login to migrate.
		return nil, unauthenticatedErr
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
		return &c.OAuthToken, nil
	}

	// Token has expired, refresh it.
	token, err := c.OAuthConfig.TokenSource(c.ctx.Context, &c.OAuthToken).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh access token: %w", err)
	}

	c.OAuthToken = *token
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
