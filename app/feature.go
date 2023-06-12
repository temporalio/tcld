package app

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/urfave/cli/v2"
)

var (
	EnableExportFeatureFlag = &cli.BoolFlag{
		Name:     "enable-export",
		Value:    false,
		Usage:    "enable export commands",
		Required: false,
	}
)

func GetFeatureFlagConfigPath() string {
	return ConfigDirFlag.Value + "/feature.json"
}

func GetFeatureFlagConfig(featureFlagConfigDir string) (map[string]bool, error) {
	// create config file if not exist
	if _, err := ioutil.ReadFile(featureFlagConfigDir); err != nil {
		if err := ioutil.WriteFile(featureFlagConfigDir, []byte("{}"), 0644); err != nil {
			return nil, err
		}
	}

	content, err := ioutil.ReadFile(featureFlagConfigDir)
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
			Flags: []cli.Flag{
				EnableExportFeatureFlag,
			},
			Action: func(c *cli.Context) error {
				featureFlagConfigDir := GetFeatureFlagConfigPath()
				jsonData, err := GetFeatureFlagConfig(featureFlagConfigDir)

				if err != nil {
					return err
				}

				if c.Bool(EnableExportFeatureFlag.Name) {
					jsonData[EnableExportFeatureFlag.Name] = true
					fmt.Println("Export feature enabled")

				}

				jsonString, err := json.Marshal(jsonData)
				if err != nil {
					return err
				}

				if err := ioutil.WriteFile(featureFlagConfigDir, jsonString, 0644); err != nil {
					return err
				}
				return nil
			},
		},
	}, nil
}
