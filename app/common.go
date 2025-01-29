package app

import (
	"encoding/json"
	"fmt"
	"regexp"

	apipayload "github.com/temporalio/tcld/protogen/temporal/api/common/v1"
)

const (
	CloudProviderGCP = "gcp"
	CloudProviderAWS = "aws"
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

func newAPIPayloadFromString(str string) *apipayload.Payload {
	// Alternatively, use "go.temporal.io/sdk/converter" package
	// converter.GetDefaultDataConverter().ToPayload(data)
	data, err := json.Marshal(str)
	if err != nil {
		panic(fmt.Errorf("failed to marshal description to JSON: %w", err))
	}

	return &apipayload.Payload{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     data,
	}
}
