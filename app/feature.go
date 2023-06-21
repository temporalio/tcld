package app

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

func getFeatureFlagJSON() ([]FeatureFlag, error) {
	featureFlagConfigPath := getFeatureFlagConfigPath()
	return getFeatureFlagConfig(featureFlagConfigPath)
}

func getFeatureFlagConfigPath() string {
	return filepath.Join(ConfigDirFlag.Value, featureflagFileName)
}

func getFeatureFlagConfig(featureFlagConfigPath string) ([]FeatureFlag, error) {
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

	var jsonData []FeatureFlag
	err = json.Unmarshal(content, &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func toggle_feature(feature string) error {
	featureFlagConfigPath := getFeatureFlagConfigPath()
	return toggle_feature_save_to_path(feature, featureFlagConfigPath)
}

func toggle_feature_save_to_path(feature string, path string) error {
	jsonData, err := getFeatureFlagConfig(path)

	if err != nil {
		return err
	}

	found := false
	for i, featureflag := range jsonData {
		if featureflag.Name == feature {
			jsonData[i].Value = !featureflag.Value
			found = true
			println("Feature flag", feature, "is now", jsonData[i].Value)
		}
	}

	if !found {
		jsonData = append(jsonData, FeatureFlag{
			Name:  feature,
			Value: true,
		})
		println("Feature flag", feature, "is now", true)
	}

	output, err := json.Marshal(jsonData)

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
						return toggle_feature(ExportFeatureFlag)
					},
				},
				{
					Name:    "get",
					Aliases: []string{"g"},
					Usage:   "get all feature flags Value",
					Action: func(c *cli.Context) error {
						jsonData, err := getFeatureFlagJSON()

						if err != nil {
							return err
						}
						jsonString, err := json.Marshal(jsonData)
						if err != nil {
							return err
						}

						fmt.Println(string(jsonString))

						return nil
					},
				},
			},
		},
	}, nil
}
