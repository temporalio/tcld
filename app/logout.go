package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

func NewLogoutCommand() (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "logout",
		Usage:   "Logout current user",
		Aliases: []string{"lo"},
		Flags: []cli.Flag{
			domainFlag,
			disablePopUpFlag,
		},
		Action: func(ctx *cli.Context) error {
			configDir := ctx.Path(ConfigDirFlagName)
			if err := removeFile(filepath.Join(configDir, tokenConfigFile)); err != nil {
				return fmt.Errorf("unable to remove config file: %w", err)
			}

			logoutURL := fmt.Sprintf("https://%s/v2/logout", ctx.String("domain"))

			return openBrowser(ctx, "Logout via this url", logoutURL)
		},
	}}, nil
}

func removeFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}
