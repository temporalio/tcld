package app

import (
	"flag"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func NewTestApp(t *testing.T, cmds []*cli.Command, flags []cli.Flag) (*cli.App, string) {
	tmpDir := t.TempDir()
	ConfigDirFlag.Value = tmpDir
	disablePopUpFlag.Value = true
	AutoConfirmFlag.Value = true

	return &cli.App{
		Name:     t.Name(),
		Commands: cmds,
		Flags:    flags,
	}, tmpDir
}

func NewTestContext(t *testing.T, app *cli.App) *cli.Context {
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	for _, f := range app.Flags {
		require.NoError(t, f.Apply(fs))
	}
	fs.SetOutput(io.Discard)

	return cli.NewContext(app, fs, nil)
}
