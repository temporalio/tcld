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
		Usage: "temporal cloud cli",
		Flags: []cli.Flag{
			ServerFlag,
			ConfigDirFlag,
			AutoConfirmFlag,
		},
	}
	app.Commands = params.Commands
	return app, nil
}
