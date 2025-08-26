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
	// Filter out nil commands (for disabled features)
	var enabledCommands []*cli.Command
	for _, cmd := range params.Commands {
		if cmd != nil {
			enabledCommands = append(enabledCommands, cmd)
		}
	}

	app := &cli.App{
		Name:  "tcld",
		Usage: "Temporal Cloud cli",
		Flags: []cli.Flag{
			ServerFlag,
			TLSServerNameFlag,
			ConfigDirFlag,
			AutoConfirmFlag,
			IdempotentFlag,
			APIKeyFlag,
			InsecureConnectionFlag,
			EnableDebugLogsFlag,
		},
		Commands: enabledCommands,
	}

	return app, nil
}
