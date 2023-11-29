package app

import (
	"fmt"
	"regexp"
)

var (
	assumedRolePattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/(\S+)$`)
	saPrincipalPattern = regexp.MustCompile(`^(\S+)@(\S+).iam.gserviceaccount.com$`)
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
	var accountID, roleName string
	re := assumedRolePattern
	submatch := re.FindStringSubmatch(assumedRole)

	if len(submatch) != 3 {
		return "", "", fmt.Errorf("invalid assumed role: %s", assumedRole)
	}

	accountID = submatch[1]
	roleName = submatch[2]

	return accountID, roleName, nil
}

func parseSAPrincipal(saPrincipal string) (string, string, error) {
	var gcpProjectId, saId string
	re := saPrincipalPattern
	submatch := re.FindStringSubmatch(saPrincipal)

	if len(submatch) != 3 {
		return "", "", fmt.Errorf("invalid SA principal: %s", saPrincipal)
	}

	saId = submatch[1]
	gcpProjectId = submatch[2]

	return saId, gcpProjectId, nil
}

func getAssumedRoleArn(awsAccountId string, awsRoleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", awsAccountId, awsRoleName)
}

func getSAPrincipal(saName string, gcpProjectName string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", saName, gcpProjectName)
}
