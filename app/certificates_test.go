package app

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/urfave/cli/v2"
)

func TestCertificates(t *testing.T) {
	suite.Run(t, new(CertificatesTestSuite))
}

type CertificatesTestSuite struct {
	suite.Suite
	cliApp   *cli.App
	mockCtrl *gomock.Controller
}

func (s *CertificatesTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())

	out, err := NewCertificatesCommand()
	s.Require().NoError(err)

	AutoConfirmFlag.Value = true
	s.cliApp = &cli.App{
		Name:     "test",
		Commands: []*cli.Command{out.Command},
		Flags: []cli.Flag{
			AutoConfirmFlag,
		},
	}
}

func (s *CertificatesTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *CertificatesTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *CertificatesTestSuite) TestCertificateGenerateCore() {
	type args struct {
		rsa                     bool
		caValidityPeriod        time.Duration
		endEntityValidityPeriod time.Duration
		organization            string
	}
	tests := []struct {
		name                      string
		args                      args
		caGenerationErrMsg        string
		endEntityGenerationErrMsg string
	}{
		{
			"success - defaults",
			args{
				organization:     "test-certificate",
				caValidityPeriod: 365 * 24 * time.Hour,
			},
			"",
			"",
		},
		{
			"success - options",
			args{
				rsa:                     true,
				organization:            "test-certificate",
				caValidityPeriod:        365 * 24 * time.Hour,
				endEntityValidityPeriod: 24 * time.Hour,
			},
			"",
			"",
		},
		{
			"failure - missing required fields",
			args{},
			"Error:Field validation for 'Organization' failed on the 'required' tag",
			"",
		},
		{
			"failure - end-entity validity period too big",
			args{
				rsa:                     true,
				organization:            "test-certificate",
				caValidityPeriod:        365 * 24 * time.Hour,
				endEntityValidityPeriod: 500 * 24 * time.Hour,
			},
			"",
			"validity period of 12000h0m0s puts certificate's expiry after certificate authority's expiry",
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			caPem, caPrivKeyPem, err := generateCACertificate(generateCACertificateInput{
				Organization:   tt.args.organization,
				ValidityPeriod: tt.args.caValidityPeriod,
				RSAAlgorithm:   tt.args.rsa,
			})

			if tt.caGenerationErrMsg == "" {
				s.NoError(err, "ca cert generation failed")
			} else {
				s.Error(err, "expected ca cert generation to fail")
				s.ErrorContains(err, tt.caGenerationErrMsg)
				return
			}

			_, _, err = generateEndEntityCertificate(generateEndEntityCertificateInput{
				Organization:    tt.args.organization + "-leaf",
				ValidityPeriod:  tt.args.endEntityValidityPeriod,
				CaPem:           caPem,
				CaPrivateKeyPEM: caPrivKeyPem,
			})

			if tt.endEntityGenerationErrMsg == "" {
				s.NoError(err, "end-entity cert generation failed")
			} else {
				s.Error(err, "expected end-entity cert generation to fail")
				s.ErrorContains(err, tt.endEntityGenerationErrMsg)
			}
		})
	}
}

func (s *CertificatesTestSuite) TestGenerateCACertificateCMD() {
	tests := []struct {
		name         string
		args         []string
		expectErrMsg string
	}{
		{
			name:         "generate ca success",
			args:         []string{"gen", "ca", "--org", "testorg", "-d", "8d", "--ca-cert", "/tmp/" + uuid.NewString(), "--ca-key", "/tmp/" + uuid.NewString()},
			expectErrMsg: "",
		},
		{
			name:         "generate ca failure - validity period too short",
			args:         []string{"gen", "ca", "--org", "testorg", "-d", "3d", "--ca-cert", "/tmp/" + uuid.NewString(), "--ca-key", "/tmp/" + uuid.NewString()},
			expectErrMsg: "validity-period cannot be less than: 168h0m0s",
		},
		{
			name:         "generate ca failure - validity period too long",
			args:         []string{"gen", "ca", "--org", "testorg", "-d", "1000d", "--ca-cert", "/tmp/" + uuid.NewString(), "--ca-key", "/tmp/" + uuid.NewString()},
			expectErrMsg: "validity-period cannot be more than: 8760h0m0s",
		},
		{
			name:         "generate ca failure - validity period malformed",
			args:         []string{"gen", "ca", "--org", "testorg", "-d", "malformed", "--ca-cert", "/tmp/" + uuid.NewString(), "--ca-key", "/tmp/" + uuid.NewString()},
			expectErrMsg: "failed to parse validity-period: time: invalid duration",
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			err := s.RunCmd(tc.args...)
			if tc.expectErrMsg != "" {
				s.Error(err)
				s.ErrorContains(err, tc.expectErrMsg)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *CertificatesTestSuite) TestGenerateCertificateCMDEndToEnd() {
	caCertFile := "/tmp/" + uuid.NewString()
	caKeyFile := "/tmp/" + uuid.NewString()
	leafCertFile := "/tmp/" + uuid.NewString()
	leafKeyFile := "/tmp/" + uuid.NewString()

	s.NoError(s.RunCmd([]string{"gen", "ca", "--org", "testorg", "-d", "8d", "--ca-cert", caCertFile, "--ca-key", caKeyFile}...))
	s.NoError(s.RunCmd([]string{"gen", "leaf", "--org", "testorg", "-d", "1d", "--ca-cert", caCertFile, "--ca-key", caKeyFile, "--cert", leafCertFile, "--key", leafKeyFile}...))

	s.ErrorContains(
		s.RunCmd([]string{"gen", "leaf", "--org", "testorg", "-d", "malformed", "--ca-cert", caCertFile, "--ca-key", caKeyFile, "--cert", leafCertFile, "--key", leafKeyFile}...),
		"failed to parse validity-period: time: invalid duration",
	)

	s.ErrorContains(
		s.RunCmd([]string{"gen", "leaf", "--org", "testorg", "-d", "100d", "--ca-cert", caCertFile, "--ca-key", caKeyFile, "--cert", leafCertFile, "--key", leafKeyFile}...),
		"failed to generate end-entity certificate: validity period of 2400h0m0s puts certificate's expiry after certificate authority's expiry",
	)
}
