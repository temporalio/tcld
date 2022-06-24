package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type certificateFilter struct {
	CommonName             string `json:"commonName"`
	Organization           string `json:"organization"`
	OrganizationalUnit     string `json:"organizationalUnit"`
	SubjectAlternativeName string `json:"subjectAlternativeName"`
}

type certificateFilters []certificateFilter

func parseCertificateFilters(jsonFilters string) (certificateFilters, error) {
	if len(strings.TrimSpace(jsonFilters)) == 0 {
		return certificateFilters{}, nil
	}

	var filters certificateFilters
	if err := json.Unmarshal([]byte(jsonFilters), &filters); err != nil {
		return certificateFilters{}, err
	}

	if err := filters.validate(); err != nil {
		return certificateFilters{}, err
	}

	return filters, nil
}

func (filters certificateFilters) validate() error {
	if len(filters) == 0 {
		return nil
	}

	seenSet := make(map[certificateFilter]struct{})

	for _, filter := range filters {
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

func isFieldSet(fieldValue string) bool {
	return len(strings.TrimSpace(fieldValue)) > 0
}