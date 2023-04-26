package app

import (
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

const (
	ServerFlagName             = "server"
	ConfigDirFlagName          = "config-dir"
	RetentionDaysFlagName      = "retention-days"
	NamespaceFlagName          = "namespace"
	RequestIDFlagName          = "request-id"
	ResourceVersionFlagName    = "resource-version"
	APIKeyIDFlagName           = "api-key-id"
	APISecretKeyFlagName       = "api-secret-key"
	EnableHMACFlagName         = "enable-hmac"
	InsecureConnectionFlagName = "insecure"
	EnableDebugLogsFlagName    = "enable-debug-logs"
	AuthenticationFlagCategory = "Authentication:"

	// APIKeyVersionTag indicates the state of API keys. This should be removed when fully released.
	APIKeyVersionTag = "alpha"
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
	APIKeyIDFlag = &cli.StringFlag{
		Name:     APIKeyIDFlagName,
		Usage:    "The API key ID used for authentication (alpha)",
		EnvVars:  []string{"TEMPORAL_CLOUD_API_KEY_ID"},
		Category: AuthenticationFlagCategory,
	}
	APIKeySecretFlag = &cli.StringFlag{
		Name:     APISecretKeyFlagName,
		Usage:    "The API secret key used for authentication (" + APIKeyVersionTag + ")",
		EnvVars:  []string{"TEMPORAL_CLOUD_API_SECRET_KEY"},
		Category: AuthenticationFlagCategory,
	}
	EnableHMACFlag = &cli.BoolFlag{
		Name:     EnableHMACFlagName,
		Usage:    "Enable the use of HMAC request signatures, requires setting an API key as well (" + APIKeyVersionTag + ")",
		EnvVars:  []string{"TEMPORAL_CLOUD_ENABLE_HMAC"},
		Category: AuthenticationFlagCategory,
		// Hide the enable HMAC flag as this is an artifact of experimenting with authentication methods, and will
		// likely be removed in the next few weeks.
		Hidden: true,
	}
	InsecureConnectionFlag = &cli.BoolFlag{
		Name:     InsecureConnectionFlagName,
		Usage:    "Use an insecure transport for connection, recommended to avoid this option unless necessary",
		EnvVars:  []string{"TEMPORAL_CLOUD_INSECURE_CONNECTION"},
		Category: AuthenticationFlagCategory,
		// Hide the insecure flag because credentials should not be sent over an insecure connections. However some
		// users may be using a service mesh or local proxy, which is insecure locally but uses TLS off the host,
		// and thus may require the use of this.
		Hidden: true,
	}
	EnableDebugLogsFlag = &cli.BoolFlag{
		Name:    EnableDebugLogsFlagName,
		Usage:   "A flag to enable debug logs",
		EnvVars: []string{"TEMPORAL_CLOUD_ENABLE_DEBUG_LOGS"},
	}
)
