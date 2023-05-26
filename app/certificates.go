package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/temporalio/tcld/utils"
	"github.com/urfave/cli/v2"
)

const (
	maxCADuration = 365 * 24 * time.Hour
	minCADuration = 7 * 24 * time.Hour

	caPrivateKeyFileFlagName       = "ca-key-file"
	certificateFilterFileFlagName  = "certificate-filter-file"
	certificateFilterInputFlagName = "certificate-filter-input"

	pemEncodingCertificateType = "CERTIFICATE"
	pemEncodingPrivateKeyType  = "PRIVATE KEY"
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
	RSAAlgorithm bool
}

func generateCACertificate(
	input generateCACertificateInput,
) (caPEM, caPrivateKeyPEM []byte, err error) {
	validator := validator.New()
	if err := validator.Struct(input); err != nil {
		return nil, nil, err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate a random serial number: %w", err)
	}

	randomLetters, err := generateRandomString(4)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate random string for dns name")
	}
	dnsRoot := fmt.Sprintf("client.root.%s.%s", input.Organization, randomLetters)

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	if input.RSAAlgorithm {
		// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
		// the context of TLS this KeyUsage is particular to RSA key exchange and
		// authentication.
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	now := time.Now().UTC()
	conf := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{input.Organization},
		},
		NotBefore:             now.Add(-time.Minute), // grace of 1 min
		NotAfter:              now.Add(input.Duration),
		IsCA:                  true,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsRoot},
		MaxPathLen:            0,
	}

	var key any
	if input.RSAAlgorithm {
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate key: %w", err)
	}

	var publicKey any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	}

	cert, err := x509.CreateCertificate(rand.Reader, conf, conf, publicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate: %w", err)
	}
	caPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(caPEMBuffer, &pem.Block{
		Type:  pemEncodingCertificateType,
		Bytes: cert,
	})
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal key: %w", err)
	}
	caPrivateKeyPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(caPrivateKeyPEMBuffer, &pem.Block{
		Type:  pemEncodingPrivateKeyType,
		Bytes: privBytes,
	})
	if err != nil {
		return nil, nil, err
	}
	return caPEMBuffer.Bytes(), caPrivateKeyPEMBuffer.Bytes(), nil
}

type generateCertificateInput struct {
	Organization     string `validate:"required"`
	OrganizationUnit string

	Duration        time.Duration
	CaPem           []byte `validate:"required"`
	CaPrivateKeyPEM []byte `validate:"required"`
}

func parseCACerts(caPem, caPrivKeyPem []byte) (*x509.Certificate, any, bool, error) {

	pemBlock, _ := pem.Decode(caPem)
	if pemBlock == nil {
		return nil, nil, false, fmt.Errorf("decoding ca cert failed")
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, nil, false, fmt.Errorf("decoding ca cert failed: %w", err)
	}
	pemBlock, _ = pem.Decode(caPrivKeyPem)
	if pemBlock == nil {
		return nil, nil, false, fmt.Errorf("decoding ca key failed")
	}
	caPrivateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parsing ca key failed: %w", err)
	}
	_, isRSA := caPrivateKey.(*rsa.PrivateKey)
	return caCert, caPrivateKey, isRSA, nil
}

func generateSerialNumber() (*big.Int, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	// Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n, err
}

func generateClientCertificate(
	input generateCertificateInput,
) (certPEM, certPrivateKeyPEM []byte, err error) {
	validator := validator.New()
	if err := validator.Struct(input); err != nil {
		return nil, nil, err
	}
	caCert, caPrivateKey, isRSA, err := parseCACerts(input.CaPem, input.CaPrivateKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	randomLetters, err := generateRandomString(4)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate random string for dns name")
	}
	dnsRoot := fmt.Sprintf("client.endentity.%s.%s", input.Organization, randomLetters)
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate a random serial number: %w", err)
	}
	subject := pkix.Name{
		Organization:       []string{input.Organization},
		OrganizationalUnit: []string{input.OrganizationUnit},
	}

	now := time.Now().UTC()
	var notAfter time.Time
	if input.Duration != 0 {
		// a duration was provided by the user, validate it
		notAfter = now.Add(input.Duration).UTC()
		if notAfter.After(caCert.NotAfter.UTC()) {
			return nil, nil, fmt.Errorf("duration of %s puts certificate's expiry after certificate authority's expiry %s by %s",
				input.Duration, caCert.NotAfter.UTC().String(), notAfter.Sub(caCert.NotAfter.UTC()))
		}
	} else {
		// set notAfter to ca's notAfter when duration is not set
		notAfter = caCert.NotAfter.UTC()
	}
	conf := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now.Add(-time.Minute), // grace of 1 min
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsRoot},
	}
	var key any
	if isRSA {
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate key: %w", err)
	}

	var publicKey any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	}
	cert, err := x509.CreateCertificate(rand.Reader, conf, caCert, publicKey, caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	certPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(certPEMBuffer, &pem.Block{
		Type:  pemEncodingCertificateType,
		Bytes: cert,
	})
	if err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal key: %w", err)
	}
	certPrivateKeyPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(certPrivateKeyPEMBuffer, &pem.Block{
		Type:  pemEncodingPrivateKeyType,
		Bytes: privBytes,
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
			Aliases: []string{"gen"},
			Usage:   "Generate tls certificates",
			Subcommands: []*cli.Command{
				{
					Name:    "certificate-authority",
					Usage:   "Generate a certificate authority",
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
							Usage:    "The duration of the ca certificate, for example: 30d10h (30 days and 10 hrs)",
							Aliases:  []string{"d"},
							Required: true,
							Action: func(_ *cli.Context, v string) error {
								d, err := utils.ParseDuration(v)
								if err != nil {
									return fmt.Errorf("failed to parse duration: %w", err)
								}
								if d > maxCADuration {
									return fmt.Errorf("duration cannot be more than: %s", maxCADuration)
								}
								if d <= minCADuration {
									return fmt.Errorf("duration cannot be less than: %s", minCADuration)
								}
								return nil
							},
						},
						&cli.PathFlag{
							Name:     CaCertificateFileFlagName,
							Usage:    "The path of the file to store the generated certificate-authority in",
							Aliases:  []string{"ca-cert"},
							Required: true,
						},
						&cli.PathFlag{
							Name:     caPrivateKeyFileFlagName,
							Usage:    "The path of the file to store the generated certificate-authority's (private) key in",
							Aliases:  []string{"ca-key"},
							Required: true,
						},
						&cli.BoolFlag{
							Name:    "rsa-algorithm",
							Aliases: []string{"rsa"},
							Usage:   "Generate the certificate-authority using the RSA algorithm instead of ecdsa (optional)",
						},
					},
					Action: func(ctx *cli.Context) error {
						duration, err := utils.ParseDuration(ctx.String("duration"))
						if err != nil {
							return fmt.Errorf("failed to parse duration: %w", err)
						}
						caPem, caPrivKey, err := generateCACertificate(generateCACertificateInput{
							Organization: ctx.String("organization"),
							Duration:     duration,
							RSAAlgorithm: ctx.Bool("rsa-algorithm"),
						})
						if err != nil {
							return fmt.Errorf("failed to generate ca certificate: %w", err)
						}

						return writeCertificates(
							ctx,
							"certificate authority",
							caPem,
							caPrivKey,
							ctx.Path(CaCertificateFileFlagName),
							ctx.Path(caPrivateKeyFileFlagName),
						)
					},
				},
				{
					Name:    "client-certificate",
					Usage:   "Generate a client certificate",
					Aliases: []string{"client"},
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:     "organization",
							Usage:    "The name of the organization",
							Aliases:  []string{"org"},
							Required: true,
						},
						&cli.StringFlag{
							Name:  "organization-unit",
							Usage: "The name of the organization unit (optional)",
						},
						&cli.StringFlag{
							Name:    "duration",
							Usage:   "The duration of the client certificate, for example: 30d10h (30 days and 10 hrs), by default the generated certificates will expire when the certificate authority expires",
							Aliases: []string{"d"},
							Action: func(_ *cli.Context, v string) error {
								if _, err := utils.ParseDuration(v); err != nil {
									return fmt.Errorf("failed to parse duration: %w", err)
								}
								return nil
							},
						},
						&cli.PathFlag{
							Name:     CaCertificateFileFlagName,
							Usage:    "The path of the file where the certificate-authority is stored at",
							Aliases:  []string{"ca-cert"},
							Required: true,
						},
						&cli.PathFlag{
							Name:     caPrivateKeyFileFlagName,
							Usage:    "The path of the file where the certificate-authority's key is stored at",
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
							Name:     "key-file",
							Usage:    "The path of the file to store the generated client key in",
							Aliases:  []string{"key"},
							Required: true,
						},
					},
					Action: func(ctx *cli.Context) error {
						var duration time.Duration
						if s := ctx.String("duration"); s != "" {
							var err error
							duration, err = utils.ParseDuration(ctx.String("duration"))
							if err != nil {
								return err
							}
						}
						caPem, err := ioutil.ReadFile(ctx.Path(CaCertificateFileFlagName))
						if err != nil {
							return fmt.Errorf("failed to read ca-cert-file: %w", err)
						}
						caPrivKey, err := ioutil.ReadFile(ctx.Path(caPrivateKeyFileFlagName))
						if err != nil {
							return fmt.Errorf("failed to read ca-key-file: %w", err)
						}
						certPem, certPrivKey, err := generateClientCertificate(generateCertificateInput{
							Organization:     ctx.String("organization"),
							OrganizationUnit: ctx.String("organization-unit"),

							Duration:        duration,
							CaPem:           caPem,
							CaPrivateKeyPEM: caPrivKey,
						})
						if err != nil {
							return fmt.Errorf("failed to generate certificate: %w", err)
						}
						return writeCertificates(
							ctx,
							"client certificate",
							certPem,
							certPrivKey,
							ctx.Path("certificate-file"),
							ctx.Path("key-file"),
						)
					},
				},
			},
		},
	}, nil
}

func checkPath(ctx *cli.Context, path string) (bool, error) {
	if fi, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		// the file exists,
		switch mode := fi.Mode(); {
		case mode.IsRegular():
			yes, err := ConfirmPrompt(
				ctx,
				fmt.Sprintf("file already exists at path %s, do you want to overwrite:", path),
			)
			if err != nil {
				return false, fmt.Errorf("failed to confirm: %w", err)
			}
			return yes, nil
		case mode.IsDir():
			return false, fmt.Errorf("path cannot be a directory: %s ", path)
		default:
			return false, fmt.Errorf("invalid file path: %s (file mode=%s)", path, mode.String())
		}
	}
	return true, nil
}

func writeCertificates(ctx *cli.Context, typ string, cert, key []byte, certPath, keyPath string) error {
	if cont, err := checkPath(ctx, certPath); err != nil || !cont {
		return err
	}
	if cont, err := checkPath(ctx, keyPath); err != nil || !cont {
		return err
	}

	yes, err := ConfirmPrompt(
		ctx,
		fmt.Sprintf("storing the %s (private) key at %s, do not share this key with anyone. confirm:", typ, keyPath),
	)
	if err != nil {
		return fmt.Errorf("failed to confirm: %w", err)
	}
	if !yes {
		return nil
	}
	err = ioutil.WriteFile(certPath, cert, 0644)
	if err != nil {
		return fmt.Errorf("failed to write client certificate: %w", err)

	}
	err = ioutil.WriteFile(keyPath, key, 0600)
	if err != nil {
		return fmt.Errorf("failed to write client key: %w", err)
	}
	fmt.Printf("%s generated at: %s\n", typ, certPath)
	fmt.Printf("%s key generated at: %s\n", typ, keyPath)
	return nil
}
