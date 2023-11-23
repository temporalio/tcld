package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestVersionCommand(t *testing.T) {

	out, err := NewVersionCommand()
	assert.NoError(t, err)

	cliApp, _ := NewTestApp(t, []*cli.Command{out.Command}, nil)
	err = cliApp.Run([]string{"tcld", "version"})
	assert.NoError(t, err)
}
