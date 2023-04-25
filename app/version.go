package app

import "github.com/urfave/cli/v2"

const (
	DefaultVersion = "v0.6.0"
)

var (
	BuildDate string
	Commit    string
	Version   string
)

func NewVersionCommand() (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "version",
		Usage:   "Version information",
		Aliases: []string{"v"},
		Action: func(c *cli.Context) error {
			return PrintObj(&struct {
				BuildDate string
				Commit    string
				Version   string
			}{
				BuildDate: BuildDate,
				Commit:    Commit,
				Version:   getVersion(),
			})
		},
	}}, nil
}

func getVersion() string {
	version := Version
	if len(version) == 0 {
		version = DefaultVersion
	}
	return version
}
