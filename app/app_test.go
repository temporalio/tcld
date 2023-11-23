package app

import (
	"testing"

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
