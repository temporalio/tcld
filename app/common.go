package app

func IsFeatureEnabled(feature string) bool {
	jsonData, err := getFeatureFlagJSON()

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
