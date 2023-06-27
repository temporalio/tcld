package app

import (
	"fmt"
	"regexp"
)

var (
	assumedRolePattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/(\S+)$`)
)

func IsFeatureEnabled(feature string) bool {
	jsonData, err := getFeatureFlags()

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

func parseAssumedRole(assumedRole string) (string, string, error) {
	var accountId, roleName string
	re := assumedRolePattern
	submatch := re.FindStringSubmatch(assumedRole)

	if len(submatch) != 3 {
		return "", "", fmt.Errorf("Invalid assumed role: %s", assumedRole)
	}

	accountId = submatch[1]
	roleName = submatch[2]

	return accountId, roleName, nil
}
