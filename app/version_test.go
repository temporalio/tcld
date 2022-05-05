package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestVersionCommand(t *testing.T) {

	out, err := NewVersionCommand()
	assert.NoError(t, err)

	cliApp := &cli.App{
		Name:     "test",
		Commands: []*cli.Command{out.Command},
	}
	err = cliApp.Run([]string{"tcld", "version"})
	assert.NoError(t, err)
}
