package app

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

var (
	ExportFeatureFlag   = "enable-export"
	featureflagFileName = "feature.json"
)

type FeatureFlag struct {
	Name  string `json:"Name"`
	Value bool   `json:"Value"`
}

func getFeatureFlags() ([]FeatureFlag, error) {
	featureFlagConfigPath := getFeatureFlagConfigFilePath()
	return getFeatureFlagsFromConfigFile(featureFlagConfigPath)
}

func getFeatureFlagConfigFilePath() string {
	return filepath.Join(ConfigDirFlag.Value, featureflagFileName)
}

func getFeatureFlagsFromConfigFile(featureFlagConfigPath string) ([]FeatureFlag, error) {
	// create config file if not exist
	if _, err := os.Stat(featureFlagConfigPath); err != nil {
		if err := ioutil.WriteFile(featureFlagConfigPath, []byte("[]"), 0644); err != nil {
			return nil, err
		}
	}
	content, err := ioutil.ReadFile(featureFlagConfigPath)
	if err != nil {
		return nil, err
	}

	var featureFlags []FeatureFlag
	err = json.Unmarshal(content, &featureFlags)
	if err != nil {
		return nil, err
	}

	return featureFlags, nil
}

func toggleFeature(feature string) error {
	featureFlagConfigPath := getFeatureFlagConfigFilePath()
	return toggleFeatureSaveToPath(feature, featureFlagConfigPath)
}

func toggleFeatureSaveToPath(feature string, path string) error {
	featureFlags, err := getFeatureFlagsFromConfigFile(path)

	if err != nil {
		return err
	}

	found := false
	for i, featureflag := range featureFlags {
		if featureflag.Name == feature {
			featureFlags[i].Value = !featureflag.Value
			found = true
			println("Feature flag", feature, "is now", featureFlags[i].Value)
		}
	}

	if !found {
		featureFlags = append(featureFlags, FeatureFlag{
			Name:  feature,
			Value: true,
		})
		println("Feature flag", feature, "is now", true)
	}

	output, err := json.Marshal(featureFlags)

	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(path, output, 0644); err != nil {
		return err
	}
	return nil
}

func NewFeatureCommand() (CommandOut, error) {
	return CommandOut{
		Command: &cli.Command{
			Name:    "feature",
			Aliases: []string{"f"},
			Usage:   "feature commands",
			Hidden:  true,
			Subcommands: []*cli.Command{
				{
					Name:    "toggle-export",
					Aliases: []string{"te"},
					Usage:   "switch export on/off",
					Action: func(c *cli.Context) error {
						return toggleFeature(ExportFeatureFlag)
					},
				},
				{
					Name:    "get",
					Aliases: []string{"g"},
					Usage:   "get all feature flags Value",
					Action: func(c *cli.Context) error {
						featureFlags, err := getFeatureFlags()

						if err != nil {
							return err
						}

						// MarshalIndent the feature flags into a pretty JSON
						prettyJSON, err := json.MarshalIndent(featureFlags, "", "    ")
						if err != nil {
							log.Fatalf("Failed to generate json: %s", err)
						}

						fmt.Printf("%s\n", prettyJSON)
						return nil
					},
				},
			},
		},
	}, nil
}
