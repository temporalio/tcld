package app

import (
	"github.com/urfave/cli/v2"
	"go.uber.org/fx"
)

const (
	AppName = "tcld"
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
		Name:  AppName,
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
	for _, c := range params.Commands {
		if !IsFeatureEnabled(APIKeyFeatureFlag) && c.Name == "apikey" {
			continue
		}
		app.Commands = append(app.Commands, c)
	}
	return app, nil
}
