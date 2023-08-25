package app

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/mod/semver"
)

const (
	pseudoVersionMinLen        = len("vX.0.0-yyyymmddhhmmss-abcdefabcdef")
	pseudoVersionCommitInfoLen = len("yyyymmddhhmmss-abcdefabcdef")
)

var (
	MakeVersion string
)

type BuildInfo struct {
	Commit     string
	CommitTime time.Time
	Version    string
}

func NewVersionCommand() (CommandOut, error) {
	return CommandOut{Command: &cli.Command{
		Name:    "version",
		Usage:   "Version information",
		Aliases: []string{"v"},
		Action: func(c *cli.Context) error {
			return PrintObj(NewBuildInfo())
		},
	}}, nil
}

func NewBuildInfo() BuildInfo {
	var info BuildInfo

	di, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}

	if semver.IsValid(di.Main.Version) {
		info.Version = strings.Split(semver.Canonical(di.Main.Version), "-")[0]

		// See https://go.dev/ref/mod#pseudo-versions for more info on the expected string format
		// when the binary is compiled with go install. We always expect to hit this path if
		// di.Main.Version is a valid semver.
		if len(di.Main.Version) >= pseudoVersionMinLen {
			commitInfoStart := len(di.Main.Version) - pseudoVersionCommitInfoLen
			split := strings.Split(di.Main.Version[commitInfoStart:], "-")
			info.Commit = split[1]

			at, err := time.Parse("20060102150405", split[0])
			if err == nil {
				info.CommitTime = at
			}

			return info
		}
	} else {
		info.Version = MakeVersion
	}

	// Developer build, pull extra info from vcs.
	var hash, modified string

	for _, setting := range di.Settings {
		switch setting.Key {
		case "vcs.revision":
			hash = setting.Value
		case "vcs.modified":
			if v, err := strconv.ParseBool(setting.Value); err == nil && v {
				modified = "-modified"
			}
		case "vcs.time":
			info.CommitTime, _ = time.Parse(time.RFC3339, setting.Value)
		}
	}

	info.Commit = fmt.Sprintf("%s%s", hash, modified)

	return info
}
