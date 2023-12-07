package app

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/urfave/cli/v2"
)

const (
	// Flags.
	domainFlagName       = "domain"
	audienceFlagName     = "audience"
	clientIDFlagName     = "client-id"
	disablePopUpFlagName = "disable-pop-up"
)

var (
	domainFlag = &cli.StringFlag{
		Name:     domainFlagName,
		Value:    "login.tmprl.cloud",
		Aliases:  []string{"d"},
		Required: false,
		Hidden:   true,
	}
	audienceFlag = &cli.StringFlag{
		Name:     audienceFlagName,
		Value:    "https://saas-api.tmprl.cloud",
		Aliases:  []string{"a"},
		Required: false,
		Hidden:   true,
	}
	clientIDFlag = &cli.StringFlag{
		Name:     clientIDFlagName,
		Value:    "d7V5bZMLCbRLfRVpqC567AqjAERaWHhl",
		Aliases:  []string{"id"},
		Required: false,
		Hidden:   true,
	}
	disablePopUpFlag = &cli.BoolFlag{
		Name:     disablePopUpFlagName,
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
			_, err := login(ctx)
			return err
		},
	}}, nil
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

func openBrowser(ctx *cli.Context, message string, url string) error {
	// Print to stderr so other tooling can parse the command output.
	fmt.Fprintf(os.Stderr, "%s: %s\n", message, url)

	if ctx.Bool(disablePopUpFlagName) {
		return nil
	}

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
