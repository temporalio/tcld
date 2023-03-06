package app

import (
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

const (
	ServerFlagName          = "server"
	ConfigDirFlagName       = "config-dir"
	RetentionDaysFlagName   = "retention-days"
	NamespaceFlagName       = "namespace"
	RequestIDFlagName       = "request-id"
	ResourceVersionFlagName = "resource-version"
	ServiceNameFlagName     = "service-name"
	APIKeyIDFlagName        = "api-key-id"
	APISecretKeyFlagName    = "api-secret-key"
	EnableDebugLogsFlagName = "enable-debug-logs"
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
	RetentionDaysFlag = &cli.IntFlag{
		Name:     RetentionDaysFlagName,
		Usage:    "The retention of the namespace in days",
		Aliases:  []string{"rd"},
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
	ServiceNameFlag = &cli.StringFlag{
		Name:    ServiceNameFlagName,
		Usage:   "The service name of the server",
		Value:   "saas-api",
		Hidden:  true,
		EnvVars: []string{"TEMPORAL_CLOUD_SERVICE_NAME"},
	}
	APIKeyIDFlag = &cli.StringFlag{
		Name:    APIKeyIDFlagName,
		Usage:   "The API Key ID used for authentication",
		EnvVars: []string{"TEMPORAL_CLOUD_API_KEY_ID"},
	}
	APISecretKeyFlag = &cli.StringFlag{
		Name:    APISecretKeyFlagName,
		Usage:   "The API Secret Key used for authentication",
		EnvVars: []string{"TEMPORAL_CLOUD_API_SECRET_KEY"},
	}
	EnableDebugLogsFlag = &cli.BoolFlag{
		Name:    EnableDebugLogsFlagName,
		Usage:   "A flag to enable debug logs",
		EnvVars: []string{"TEMPORAL_CLOUD_ENABLE_DEBUG_LOGS"},
	}
)
