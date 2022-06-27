package app

import (
	"reflect"
	"testing"
)

func Test_certificateFilters_validate(t *testing.T) {
	tests := []struct {
		name    string
		filters certificateFiltersConfig
		wantErr bool
	}{
		{
			"no filters specified",
			certificateFiltersConfig{},
			false,
		},
		{
			"empty filter specified",
			certificateFiltersConfig{
				[]certificateFilter{{}},
			},
			true,
		},
		{
			"duplicate filter specified",
			certificateFiltersConfig{
				Filters: []certificateFilter{
					{CommonName: "testCN"},
					{CommonName: "testCN"},
				},
			},
			true,
		},
		{
			"two separate filters specified",
			certificateFiltersConfig{
				Filters: []certificateFilter{
					{CommonName: "testCN"},
					{CommonName: "testCN2"},
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.filters.validate(); (err != nil) != tt.wantErr {
				t.Errorf("certificateFilters.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseCertificateFilters(t *testing.T) {
	type args struct {
		jsonFilters string
	}
	tests := []struct {
		name    string
		args    args
		want    certificateFiltersConfig
		wantErr bool
	}{
		{
			"empty contents",
			args{},
			certificateFiltersConfig{},
			false,
		},
		{
			"empty array",
			args{`{ "filters": [] }`},
			certificateFiltersConfig{
				Filters: []certificateFilter{},
			},
			false,
		},
		{
			"bad json",
			args{`[`},
			certificateFiltersConfig{},
			true,
		},
		{
			"simple json",
			args{`{"filters": [{"commonName": "test1"}]}`},
			certificateFiltersConfig{
				Filters: []certificateFilter{{CommonName: "test1"}},
			},
			false,
		},
		{
			"complex json",
			args{`{ "filters": [ { "commonName": "test1" }, { "commonName": "test2" } ] }`},
			certificateFiltersConfig{
				Filters: []certificateFilter{
					{CommonName: "test1"},
					{CommonName: "test2"},
				},
			},
			false,
		},
		{
			"fail validation",
			args{`{"filters": [{}]}`},
			certificateFiltersConfig{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCertificateFilters([]byte(tt.args.jsonFilters))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCertificateFilters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCertificateFilters() = %v, want %v", got, tt.want)
			}
		})
	}
}
