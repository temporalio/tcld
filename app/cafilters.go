package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/temporalio/tcld/protogen/api/namespace/v1"
)

type certificateFilter struct {
	CommonName             string `json:"commonName"`
	Organization           string `json:"organization"`
	OrganizationalUnit     string `json:"organizationalUnit"`
	SubjectAlternativeName string `json:"subjectAlternativeName"`
}

type certificateFiltersConfig struct {
	Filters []certificateFilter `json:"filters,omitempty"`
}

func parseCertificateFilters(configJson []byte) (certificateFiltersConfig, error) {
	if len(configJson) == 0 {
		return certificateFiltersConfig{}, nil
	}

	var filters certificateFiltersConfig
	if err := json.Unmarshal(configJson, &filters); err != nil {
		return certificateFiltersConfig{}, err
	}

	if err := filters.validate(); err != nil {
		return certificateFiltersConfig{}, err
	}

	return filters, nil
}

func (config certificateFiltersConfig) validate() error {
	seenSet := make(map[certificateFilter]struct{})

	for _, filter := range config.Filters {
		if !isFieldSet(filter.CommonName) && !isFieldSet(filter.Organization) && !isFieldSet(filter.OrganizationalUnit) && !isFieldSet(filter.SubjectAlternativeName) {
			return errors.New("certificate filter must have at least one field set")
		}

		if _, ok := seenSet[filter]; ok {
			return fmt.Errorf("supplied certificate filters contain at least one duplicate entry: '%+v'", filter)
		}

		seenSet[filter] = struct{}{}
	}

	return nil
}

func (config certificateFiltersConfig) toSpec() []*namespace.CertificateFilterSpec {
	var results []*namespace.CertificateFilterSpec

	for _, filter := range config.Filters {
		results = append(results, &namespace.CertificateFilterSpec{
			CommonName:             filter.CommonName,
			Organization:           filter.Organization,
			OrganizationalUnit:     filter.OrganizationalUnit,
			SubjectAlternativeName: filter.SubjectAlternativeName,
		})
	}

	return results
}

func fromSpec(filters []*namespace.CertificateFilterSpec) certificateFiltersConfig {
	var result certificateFiltersConfig

	for _, filter := range filters {
		result.Filters = append(result.Filters, certificateFilter{
			CommonName:             filter.CommonName,
			Organization:           filter.Organization,
			OrganizationalUnit:     filter.OrganizationalUnit,
			SubjectAlternativeName: filter.SubjectAlternativeName,
		})
	}

	return result
}

func isFieldSet(fieldValue string) bool {
	return len(strings.TrimSpace(fieldValue)) > 0
}
