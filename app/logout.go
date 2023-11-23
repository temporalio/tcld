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

			if err := removeFile(filepath.Join(configDir, tokenFile)); err != nil {
				return fmt.Errorf("unable to remove config file: %w", err)
			}

			logoutURL := fmt.Sprintf("https://%s/v2/logout", ctx.String("domain"))
			fmt.Printf("Logout via this url: %s\n", logoutURL)

			if !ctx.Bool("disable-pop-up") {
				if err := openBrowser(logoutURL); err != nil {
					return fmt.Errorf("Unable to open browser, please open url manually.")
				}
			}

			return nil
		},
	}}, nil
}

func removeFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}
