package app

func IsFeatureEnabled(feature string) bool {
	featureFlagConfigPath := getFeatureFlagConfigPath()
	jsonData, err := getFeatureFlagConfig(featureFlagConfigPath)

	if err != nil {
		return false
	}

	for _, featureFlag := range jsonData {
		if featureFlag.Name == feature {
			return featureFlag.Value
		}
	}

	return false
}
