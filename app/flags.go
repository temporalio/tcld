package app

import (
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

const (
	ServerFlagName          = "server"
	ConfigDirFlagName       = "config-dir"
	RetentionFlagName       = "retention-days"
	NamespaceFlagName       = "namespace"
	RequestIDFlagName       = "request-id"
	ResourceVersionFlagName = "resource-version"
)

var (
	ServerFlag = &cli.StringFlag{
		Name:     ServerFlagName,
		Aliases:  []string{"s"},
		Value:    "saas-api.tmprl.cloud:443",
		Usage:    "saas-api server endpoint",
		EnvVars:  []string{"TEMPORAL_CLOUD_API_SERVER"},
		Hidden:   true,
		Required: false,
	}
	ConfigDirFlag = &cli.PathFlag{
		Name:     ConfigDirFlagName,
		Value:    filepath.Join(os.Getenv("HOME"), ".config", "tcld"),
		Usage:    "The config directory to use",
		Hidden:   true,
		Required: false,
	}
	RetentionFlag = &cli.StringFlag{
		Name:     RetentionFlagName,
		Usage:    "The retention of the namespace",
		Aliases:  []string{"ret"},
		EnvVars:  []string{"NAMESPACE_RETENTION"},
		Required: true,
	}
	NamespaceFlag = &cli.StringFlag{
		Name:     NamespaceFlagName,
		Usage:    "The namespace hosted on temporal cloud",
		Aliases:  []string{"n"},
		EnvVars:  []string{"TEMPORAL_CLOUD_NAMESPACE"},
		Required: true,
	}
	RequestIDFlag = &cli.StringFlag{
		Name:    RequestIDFlagName,
		Usage:   "The request-id to use for the asynchronous operation, if not set the server will assign one (optional)",
		Aliases: []string{"r"},
	}
	ResourceVersionFlag = &cli.StringFlag{
		Name:    ResourceVersionFlagName,
		Usage:   "The resource-version (etag) to update from, if not set the cli will use the latest (optional)",
		Aliases: []string{"v"},
	}
)
