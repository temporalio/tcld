package app

import (
	"fmt"
	"github.com/urfave/cli/v2"
)

func NewLogoutCommand(c *LoginClient) (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "logout",
		Usage:   "Logout current user",
		Aliases: []string{"lo"},
		Flags: []cli.Flag{
			domainFlag,
			disablePopUpFlag,
		},
		Action: func(ctx *cli.Context) error {
			logoutURL := fmt.Sprintf("https://%s/v2/logout", ctx.String("domain"))
			fmt.Printf("Logout via this url: %s\n", logoutURL)
			if !ctx.Bool("disable-pop-up") {
				if err := c.loginService.OpenBrowser(logoutURL); err != nil {
					return fmt.Errorf("Unable to open browser, please open url manually.")
				}
			}
			return nil
		},
	}}, nil
}
