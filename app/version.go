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
	// MinSupportedVersion is the minimum tcld version supported by our APIs.
	// This string must be updated when we deprecate older versions, but should be
	// done carefully as this will likely break user's current usage of tcld.
	MinSupportedVersion = "v0.1.3"

	// DefaultVersionString is the version which is sent over if no version was available.
	// This can happen if a user builds the latest main branch, as the version string provided
	// to us from Go tooling is `(devel)`
	DefaultVersionString = MinSupportedVersion + "-no-version-available"

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
	if !semver.IsValid(di.Main.Version) {
		info.Version = DefaultVersionString
	}

	if len(di.Main.Version) >= pseudoVersionMinLen {
		// Used when compiled with `go install`.
		// See https://go.dev/ref/mod#pseudo-versions for more info on the expected string format
		commitInfoStart := len(di.Main.Version) - pseudoVersionCommitInfoLen
		split := strings.Split(di.Main.Version[commitInfoStart:], "-")

		// Make the time human readable.
		at, err := time.Parse("20060102150405", split[0])
		if err == nil {
			info.Date = at.UTC().Format("2006-01-02T15:04:05.000Z")
		}
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
