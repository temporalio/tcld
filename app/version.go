package app

import "github.com/urfave/cli/v2"

var (
	BuildDate string
	Commit    string
	Version   string
)

func NewVersionCommand() (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "version",
		Usage:   "version information",
		Aliases: []string{"v"},
		Action: func(c *cli.Context) error {
			return PrintObj(&struct {
				BuildDate string
				Commit    string
				Version   string
			}{
				BuildDate: BuildDate,
				Commit:    Commit,
				Version:   Version,
			})
		},
	}}, nil
}
