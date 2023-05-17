package app

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/temporalio/tcld/utils"
	"github.com/urfave/cli/v2"
)

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

type generateCACertificateInput struct {
	Organization string        `validate:"required"`
	Duration     time.Duration `validate:"required"`
}

func generateCACertificate(
	input generateCACertificateInput,
) (caPEM, caPrivateKeyPEM []byte, err error) {

	validator := validator.New()
	if err := validator.Struct(input); err != nil {
		return nil, nil, err
	}
	randomLetters, err := generateRandomString(4)
	if err != nil {
		return nil, nil, err
	}
	dnsRoot := fmt.Sprintf("client.root.%s.%s", input.Organization, randomLetters)
	now := time.Now()
	conf := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{input.Organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(input.Duration),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsRoot},
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, conf, conf, privateKey.Public(), privateKey)
	if err != nil {
		return nil, nil, err
	}

	caPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(caPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return nil, nil, err
	}

	caPrivateKeyPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(caPrivateKeyPEMBuffer, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, nil, err
	}
	return caPEMBuffer.Bytes(), caPrivateKeyPEMBuffer.Bytes(), nil
}

type generateCertificateInput struct {
	Organization     string `validate:"required"`
	OrganizationUnit string

	Duration        time.Duration `validate:"required"`
	CaPem           []byte        `validate:"required"`
	CaPrivateKeyPEM []byte        `validate:"required"`
}

func parseCACerts(caPem, caPrivKeyPem []byte) (*x509.Certificate, *rsa.PrivateKey, error) {

	pemBlock, _ := pem.Decode(caPem)
	if pemBlock == nil {
		return nil, nil, fmt.Errorf("decoding ca cert failed")
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding ca cert failed: %s", err)
	}
	pemBlock, _ = pem.Decode(caPrivKeyPem)
	if pemBlock == nil {
		return nil, nil, fmt.Errorf("decoding ca private key failed")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing ca private key failed: %s", err)
	}
	return caCert, caPrivateKey, nil
}

func generateCertificate(
	input generateCertificateInput,
) (certPEM, certPrivateKeyPEM []byte, err error) {
	validator := validator.New()
	if err := validator.Struct(input); err != nil {
		return nil, nil, err
	}
	caCert, caPrivateKey, err := parseCACerts(input.CaPem, input.CaPrivateKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	randomLetters, err := generateRandomString(4)
	if err != nil {
		return nil, nil, err
	}
	subject := pkix.Name{
		Organization:       []string{input.Organization},
		OrganizationalUnit: []string{input.OrganizationUnit},
	}
	dnsRoot := fmt.Sprintf("client.endentity.%s.%s", input.Organization, randomLetters)
	now := time.Now()
	conf := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(input.Duration),
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsRoot},
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, conf, caCert, privateKey.Public(), caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(certPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return nil, nil, err
	}

	certPrivateKeyPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(certPrivateKeyPEMBuffer, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return nil, nil, err
	}
	return certPEMBuffer.Bytes(), certPrivateKeyPEMBuffer.Bytes(), nil
}

func NewCertificatesCommand() (CommandOut, error) {
	return CommandOut{
		Command: &cli.Command{
			Name:    "generate-certificates",
			Aliases: []string{"certs"},
			Usage:   "Generate certificates.",
			Subcommands: []*cli.Command{
				{
					Name:    "certificate-authority",
					Usage:   "generate a certificate authority",
					Aliases: []string{"ca"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "organization",
							Usage:    "The name of the organization",
							Aliases:  []string{"org"},
							Required: true,
						},
						&cli.StringFlag{
							Name:     "duration",
							Usage:    "The duration of the ca certificate, for example: 1y30d (1 year and 30 days)",
							Aliases:  []string{"d"},
							Required: true,
							Action: func(_ *cli.Context, v string) error {
								// make sure we can parse the duration
								_, err := utils.ParseDuration(v)
								return err
							},
						},
						&cli.PathFlag{
							Name:     CaCertificateFileFlagName,
							Usage:    "The path of the file to store the generated certificate-authority in",
							Aliases:  []string{"ca-cert"},
							Required: true,
						},
						&cli.PathFlag{
							Name:     CaPrivateKeyFileFlagName,
							Usage:    "The path of the file to store the generated certificate-authority's private key in",
							Aliases:  []string{"ca-key"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						duration, err := utils.ParseDuration(ctx.String("duration"))
						if err != nil {
							return err
						}
						caPem, caPrivKey, err := generateCACertificate(generateCACertificateInput{
							Organization: ctx.String("organization"),
							Duration:     duration,
						})
						if err != nil {
							return fmt.Errorf("failed to generate ca certificate: %s", err)
						}
						yes, err := ConfirmPrompt(
							ctx,
							fmt.Sprintf("storing certificate authority's private key at %s, do not share this key with anyone. confirm: ",
								ctx.Path(CaPrivateKeyFileFlagName),
							),
						)
						if err != nil || !yes {
							return nil
						}
						err = ioutil.WriteFile(
							ctx.Path(CaCertificateFileFlagName),
							caPem,
							0600,
						)
						if err != nil {
							return fmt.Errorf("failed to write ca certificate: %s", err)

						}
						err = ioutil.WriteFile(
							ctx.Path(CaPrivateKeyFileFlagName),
							caPrivKey,
							0600,
						)
						if err != nil {
							return fmt.Errorf("failed to write ca private key: %s", err)
						}

						return nil
					},
				},
				{
					Name:    "client-certificate",
					Aliases: []string{"cert"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "organization",
							Usage:    "The name of the organization",
							Aliases:  []string{"org"},
							Required: true,
						},
						&cli.StringFlag{
							Name:  "organization-unit",
							Usage: "The name of the organization unit",
						},
						&cli.StringFlag{
							Name:     "duration",
							Usage:    "The duration of the client certificate, for example: 1y30d (1 year and 30 days)",
							Aliases:  []string{"d"},
							Required: true,
							Action: func(_ *cli.Context, v string) error {
								// make sure we can parse the duration
								_, err := utils.ParseDuration(v)
								return err
							},
						},
						&cli.PathFlag{
							Name:     CaCertificateFileFlagName,
							Usage:    "The path of the file where the certificate-authority is stored at",
							Aliases:  []string{"ca-cert"},
							Required: true,
						},
						&cli.PathFlag{
							Name:     CaPrivateKeyFileFlagName,
							Usage:    "The path of the file where the certificate-authority's private key is stored at",
							Aliases:  []string{"ca-key"},
							Required: true,
						},
						&cli.PathFlag{
							Name:     "certificate-file",
							Usage:    "The path of the file to store the generated client certificate in",
							Aliases:  []string{"cert"},
							Required: true,
						},
						&cli.PathFlag{
							Name:     "private-key-file",
							Usage:    "The path of the file to store the generated client private key in",
							Aliases:  []string{"key"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						duration, err := utils.ParseDuration(ctx.String("duration"))
						if err != nil {
							return err
						}
						caPem, err := ioutil.ReadFile(ctx.Path(CaCertificateFileFlagName))
						if err != nil {
							return fmt.Errorf("failed to read ca-cert-file: %s", err)
						}
						caPrivKey, err := ioutil.ReadFile(ctx.Path(CaPrivateKeyFileFlagName))
						if err != nil {
							return fmt.Errorf("failed to read ca-private-key-file: %s", err)
						}
						certPem, certPrivKey, err := generateCertificate(generateCertificateInput{
							Organization:     ctx.String("organization"),
							OrganizationUnit: ctx.String("organization-unit"),

							Duration:        duration,
							CaPem:           caPem,
							CaPrivateKeyPEM: caPrivKey,
						})
						if err != nil {
							return fmt.Errorf("failed to generate certificate: %s", err)
						}
						yes, err := ConfirmPrompt(
							ctx,
							fmt.Sprintf("storing the certificate private key at %s, do not share this key with anyone. confirm:",
								ctx.Path("private-key-file"),
							),
						)
						if err != nil || !yes {
							return nil
						}
						err = ioutil.WriteFile(
							ctx.Path("certificate-file"),
							certPem,
							0600,
						)
						if err != nil {
							return fmt.Errorf("failed to write ca certificate: %s", err)

						}
						err = ioutil.WriteFile(
							ctx.Path("private-key-file"),
							certPrivKey,
							0600,
						)
						if err != nil {
							return fmt.Errorf("failed to write ca private key: %s", err)
						}

						return nil
					},
				},
			},
		},
	}, nil
}
