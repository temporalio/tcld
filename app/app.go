package app

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/fx"
)

type AppParams struct {
	fx.In
	Commands []*cli.Command `group:"commands"`
}

type CommandOut struct {
	fx.Out
	Command *cli.Command `group:"commands"`
}

func NewApp(params AppParams) (*cli.App, error) {
	app := &cli.App{
		Name:  "tcld",
		Usage: "Temporal Cloud cli",
		Flags: []cli.Flag{
			ServerFlag,
			ConfigDirFlag,
			AutoConfirmFlag,
			APIKeyFlag,
			InsecureConnectionFlag,
			EnableDebugLogsFlag,
		},
	}

	var commands []*cli.Command

	for _, command := range params.Commands {
		if command.Name == "service-account" {
			if IsFeatureEnabled(ServiceAccountFeatureFlag) {
				commands = append(commands, command)
			}
		} else if command.Name == "nexus" {
			if IsFeatureEnabled(NexusFeatureFlag) {
				commands = append(commands, command)
			}
		} else {
			commands = append(commands, command)
		}
	}
	app.Commands = commands

	return app, nil
}
