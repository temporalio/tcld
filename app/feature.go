package app

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/urfave/cli/v2"
)

var (
	ExportFeatureFlag = "enable-export"
)

func GetFeatureFlagConfigPath() string {
	return ConfigDirFlag.Value + "/feature.json"
}

func GetFeatureFlagConfig(featureFlagConfigPath string) (map[string]bool, error) {
	// create config file if not exist
	if _, err := ioutil.ReadFile(featureFlagConfigPath); err != nil {
		if err := ioutil.WriteFile(featureFlagConfigPath, []byte("{}"), 0644); err != nil {
			return nil, err
		}
	}

	content, err := ioutil.ReadFile(featureFlagConfigPath)
	if err != nil {
		return nil, err
	}

	var jsonData map[string]bool
	err = json.Unmarshal(content, &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
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
						featureFlagConfigPath := GetFeatureFlagConfigPath()
						jsonData, err := GetFeatureFlagConfig(featureFlagConfigPath)

						if err != nil {
							return err
						}

						jsonData[ExportFeatureFlag] = !jsonData[ExportFeatureFlag]
						fmt.Println(ExportFeatureFlag, ":", jsonData[ExportFeatureFlag])

						jsonString, err := json.Marshal(jsonData)
						if err != nil {
							return err
						}

						if err := ioutil.WriteFile(featureFlagConfigPath, jsonString, 0644); err != nil {
							return err
						}
						return nil
					},
				},
				{
					Name:    "get",
					Aliases: []string{"g"},
					Usage:   "get all feature flags value",
					Action: func(c *cli.Context) error {
						featureFlagConfigPath := GetFeatureFlagConfigPath()
						jsonData, err := GetFeatureFlagConfig(featureFlagConfigPath)

						if err != nil {
							return err
						}

						for key, value := range jsonData {
							fmt.Println(key, ":", value)
						}

						return nil
					},
				},
			},
		},
	}, nil
}
