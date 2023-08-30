package app

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/urfave/cli/v2"
)

const (
	pseudoVersionMinLen        = len("vX.0.0-yyyymmddhhmmss-abcdefabcdef")
	pseudoVersionCommitInfoLen = len("yyyymmddhhmmss-abcdefabcdef")
)

var (
	date    string
	commit  string
	version string
)

type BuildInfo struct {
	Date    string // build time or commit time.
	Commit  string
	Version string
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

// NewBuildInfo will populate build info, to make debugging API errors easier,
// in the three scenarios a user can install tcld:
//  1. Installed via the makefile or via brew.
//  2. Installed via `go install`.
//  3. Compiled on a branch via `go build ./cmd/tcld`
func NewBuildInfo() BuildInfo {
	if len(version) > 0 {
		// Used when built with make or installed with brew.
		return BuildInfo{
			Date:    date,
			Commit:  commit,
			Version: version,
		}
	}

	di, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Printf("Failed to read debug info\n")
		return BuildInfo{}
	}

	info := BuildInfo{
		Version: di.Main.Version,
	}
	if len(di.Main.Version) >= pseudoVersionMinLen {
		// Used when compiled with `go install`.
		// See https://go.dev/ref/mod#pseudo-versions for more info on the expected string format
		commitInfoStart := len(di.Main.Version) - pseudoVersionCommitInfoLen
		split := strings.Split(di.Main.Version[commitInfoStart:], "-")

		info.Date = split[0]
		info.Commit = split[1]
	} else {
		// Used when built directly from a branch with `go build`.
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
				info.Date = setting.Value
			}
		}
		info.Commit = fmt.Sprintf("%s%s", hash, modified)
	}

	return info
}
