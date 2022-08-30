package main

import (
	"fmt"
	"os"

	"github.com/temporalio/tcld/app"
	"github.com/urfave/cli/v2"
	"go.uber.org/fx"
)

func fxOptions() fx.Option {
	return fx.Options(
		fx.Provide(
			app.NewApp,
			app.NewVersionCommand,
			app.NewAccountCommand,
			app.NewNamespaceCommand,
			app.NewRequestCommand,
			app.GetLoginClient,
			app.NewLoginCommand,
			func() app.GetNamespaceClientFn {
				return app.GetNamespaceClient
			},
			func() app.GetRequestClientFn {
				return app.GetRequestClient
			},
			func() app.GetAccountClientFn {
				return app.GetAccountClient
			},
		),
		fx.Invoke(func(app *cli.App, shutdowner fx.Shutdowner) error {
			err := app.Run(os.Args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
				os.Exit(1)
			}
			return shutdowner.Shutdown()
		}),
		fx.NopLogger,
	)
}
