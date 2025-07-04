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
			app.NewUserCommand,
			app.NewUserGroupCommand,
			app.NewRequestCommand,
			app.NewLoginCommand,
			app.NewLogoutCommand,
			app.NewCertificatesCommand,
			app.NewAPIKeyCommand,
			app.NewFeatureCommand,
			app.NewServiceAccountCommand,
			app.NewNexusCommand,
			app.NewMigrationCommand,
			app.NewConnectivityRuleCommand,
			func() app.GetNamespaceClientFn {
				return app.GetNamespaceClient
			},
			func() app.GetRequestClientFn {
				return app.GetRequestClient
			},
			func() app.GetAccountClientFn {
				return app.GetAccountClient
			},
			func() app.GetUserClientFn {
				return app.GetUserClient
			},
			func() app.GetGroupClientFn {
				return app.GetUserGroupClient
			},
			func() app.GetAPIKeyClientFn {
				return app.GetAPIKeyClient
			},
			func() app.GetServiceAccountClientFn {
				return app.GetServiceAccountClient
			},
			func() app.GetNexusClientFn {
				return app.GetNexusClient
			},
			func() app.GetMigrationClientFn {
				return app.GetMigrationClient
			},
			func() app.GetConnectivityRuleClientFn { return app.GetConnectivityRuleClient },
		),
		fx.Invoke(func(app *cli.App, shutdowner fx.Shutdowner) error {
			err := app.Run(os.Args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			}
			if shutdownErr := shutdowner.Shutdown(); shutdownErr != nil {
				fmt.Fprintf(os.Stderr, "failed to shutdown app: %s\n", shutdownErr.Error())
			}
			return err
		}),
		fx.NopLogger,
	)
}
