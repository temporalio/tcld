package main

import (
	"go.uber.org/fx/fxtest"
	"os"
	"testing"
)

func TestFxDependencyInjection(t *testing.T) {
	for k, v := range map[string]string{
		// sets up required env vars
	} {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}
	// run the version command
	os.Args = []string{"tcld", "version"}

	app := fxtest.New(t, fxOptions()).RequireStart()
	app.RequireStop()
}
