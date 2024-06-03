package utils

import (
	"fmt"
	"strings"
)

const (
	providerAWS = "aws"
	providerGCP = "gcp"
)

// compiled from https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions
var awsRegionToLocationMap = map[string]string{
	"af-south-1":     "Africa (Cape Town)",
	"ap-east-1":      "Asia Pacific (Hong Kong)",
	"ap-northeast-1": "Asia Pacific (Tokyo)",
	"ap-northeast-2": "Asia Pacific (Seoul)",
	"ap-northeast-3": "Asia Pacific (Osaka)",
	"ap-south-1":     "Asia Pacific (Mumbai)",
	"ap-south-2":     "Asia Pacific (Hyderabad)",
	"ap-southeast-1": "Asia Pacific (Singapore)",
	"ap-southeast-2": "Asia Pacific (Sydney)",
	"ap-southeast-3": "Asia Pacific (Jakarta)",
	"ap-southeast-4": "Asia Pacific (Melbourne)",
	"ca-central-1":   "Canada (Central)",
	"eu-central-1":   "Europe (Frankfurt)",
	"eu-central-2":   "Europe (Zurich)",
	"eu-north-1":     "Europe (Stockholm)",
	"eu-south-1":     "Europe (Milan)",
	"eu-south-2":     "Europe (Spain)",
	"eu-west-1":      "Europe (Ireland)",
	"eu-west-2":      "Europe (London)",
	"eu-west-3":      "Europe (Paris)",
	"il-central-1":   "Israel (Tel Aviv)",
	"me-central-1":   "Middle East (UAE)",
	"me-south-1":     "Middle East (Bahrain)",
	"sa-east-1":      "South America (Sao Paulo)",
	"us-east-1":      "US East (N. Virginia)",
	"us-east-2":      "US East (Ohio)",
	"us-west-1":      "US West (N. California)",
	"us-west-2":      "US West (Oregon)",
}

func ValidateCloudProviderAndRegion(region string) error {
	switch {
	case strings.HasPrefix(region, providerAWS+"-"):
		awsRegion := region[len(providerAWS)+1:]
		if _, ok := AWSLocationFromRegion(awsRegion); !ok {
			return fmt.Errorf("invalid aws region: %s", region)
		}
		return nil
	case strings.HasPrefix(region, providerGCP+"-"):
		gcpRegion := region[len(providerGCP)+1:]
		if len(gcpRegion) == 0 {
			return fmt.Errorf("invalid google cloud region: %s", region)
		}
		// TODO: validate GCP region
		return nil
	default:
		return fmt.Errorf("invalid region format: %s, required: <cloud prvider>-<region name>", region)
	}
}

func AWSLocationFromRegion(region string) (string, bool) {
	location, ok := awsRegionToLocationMap[region]
	return location, ok
}
