package app

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/go-playground/validator/v10"
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
	CommonName       string
	IPAddresses      []net.IP
	EmailAddresses   []string

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
		CommonName:         input.CommonName,
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
	if len(input.EmailAddresses) > 0 {
		conf.EmailAddresses = input.EmailAddresses
	}
	if len(input.IPAddresses) > 0 {
		conf.IPAddresses = input.IPAddresses
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
