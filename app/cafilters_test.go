package app

import (
	"reflect"
	"testing"
)

func Test_certificateFilters_validate(t *testing.T) {
	tests := []struct {
		name    string
		filters certificateFilters
		wantErr bool
	}{
		{
			"no filters specified",
			certificateFilters{},
			false,
		},
		{
			"empty filter specified",
			certificateFilters{
				certificateFilter{},
			},
			true,
		},
		{
			"duplicate filter specified",
			certificateFilters{
				certificateFilter{
					CommonName: "testCN",
				},
				certificateFilter{
					CommonName: "testCN",
				},
			},
			true,
		},
		{
			"two separate filters specified",
			certificateFilters{
				certificateFilter{
					CommonName: "testCN",
				},
				certificateFilter{
					CommonName: "testCN2",
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
		want    certificateFilters
		wantErr bool
	}{
		{
			"empty contents",
			args{""},
			certificateFilters{},
			false,
		},
		{
			"empty array",
			args{`[]`},
			certificateFilters{},
			false,
		},
		{
			"bad json",
			args{`[`},
			certificateFilters{},
			true,
		},
		{
			"simple json",
			args{`[ { "commonName": "test1" } ]`},
			certificateFilters{
				certificateFilter{CommonName: "test1"},
			},
			false,
		},
		{
			"complex json",
			args{`[ { "commonName": "test1" }, { "commonName": "test2" } ]`},
			certificateFilters{
				certificateFilter{CommonName: "test1"},
				certificateFilter{CommonName: "test2"},
			},
			false,
		},
		{
			"fail validation",
			args{`[{}]`},
			certificateFilters{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCertificateFilters(tt.args.jsonFilters)
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
