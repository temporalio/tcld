package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func generateCertificateHelper(
	commonName string,
	extUsage []x509.ExtKeyUsage,
	parent *x509.Certificate,
	parentPrivateKey crypto.PrivateKey,
	isCA bool,
	keyLengthBits int,
	signatureAlgorithm x509.SignatureAlgorithm,
) (*tls.Certificate, *x509.Certificate, error) {
	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:   commonName,
			Country:      []string{"USA"},
			Organization: []string{"TemporalTechnologiesTesting"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(0, 0, 1), // 1 day expiry
		BasicConstraintsValid: true,
		ExtKeyUsage:           extUsage,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign,
		SignatureAlgorithm:    signatureAlgorithm,
	}

	if ip := net.ParseIP(commonName).To4(); ip != nil {
		template.IPAddresses = []net.IP{ip}

		if ip.IsLoopback() {
			template.DNSNames = []string{"localhost"}
		}
	}

	if strings.ToLower(commonName) == "localhost" {
		template.IPAddresses = []net.IP{net.IPv6loopback, net.IPv4(127, 0, 0, 1)}
		template.DNSNames = []string{"localhost"}
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keyLengthBits)
	if err != nil {
		return &tls.Certificate{}, nil, err
	}

	if parent == nil {
		parent = template
		parentPrivateKey = privateKey
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, parent, privateKey.Public(), parentPrivateKey)
	if err != nil {
		return &tls.Certificate{}, nil, err
	}

	var tlsCert tls.Certificate
	tlsCert.Certificate = append(tlsCert.Certificate, cert)
	tlsCert.PrivateKey = privateKey

	x509cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, nil, err
	}

	return &tlsCert, x509cert, nil
}

func generateRootX509CAForTest() (string, error) {
	tlsCert, _, err := generateCertificateHelper("Temporal Development", nil, nil, nil, true, 512, x509.SHA256WithRSA)
	if err != nil {
		return "", err
	}

	b := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsCert.Certificate[0],
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&b))), nil
}

func TestCABundleParser(t *testing.T) {

	cert1, err := generateRootX509CAForTest()
	assert.NoError(t, err)
	cert2, err := generateRootX509CAForTest()
	assert.NoError(t, err)

	// invalid base64 encoded data
	_, err = parseCertificates("temporal cloud not base 64 encoded")
	assert.Error(t, err)

	// pass an empty
	out, err := parseCertificates(base64.StdEncoding.EncodeToString([]byte{}))
	assert.NoError(t, err)
	assert.Len(t, out, 0)

	// 2 certs
	encodedBundle := base64.StdEncoding.EncodeToString([]byte(cert1 + "\n" + cert2))
	out, err = parseCertificates(encodedBundle)
	assert.NoError(t, err)
	assert.Len(t, out, 2)
	decodedCert1, err := base64.StdEncoding.DecodeString(out[0].Base64EncodedData)
	assert.NoError(t, err)
	assert.Equal(t, cert1, string(decodedCert1))
	decodedCert2, err := base64.StdEncoding.DecodeString(out[1].Base64EncodedData)
	assert.NoError(t, err)
	assert.Equal(t, cert2, string(decodedCert2))
	outBundle, err := out.bundle()
	assert.NoError(t, err)
	assert.Equal(t, encodedBundle, outBundle)

	// 1 cert
	encodedBundle = base64.StdEncoding.EncodeToString([]byte(cert1))
	out, err = parseCertificates(encodedBundle)
	assert.NoError(t, err)
	assert.Len(t, out, 1)
	decodedCert1, err = base64.StdEncoding.DecodeString(out[0].Base64EncodedData)
	assert.NoError(t, err)
	assert.Equal(t, cert1, string(decodedCert1))
	outBundle, err = out.bundle()
	assert.NoError(t, err)
	assert.Equal(t, encodedBundle, outBundle)

	// partial cert
	encodedBundle = base64.StdEncoding.EncodeToString([]byte(cert1[:len(cert1)-20]))
	out, err = parseCertificates(encodedBundle)
	assert.Error(t, err)

	// partial cert
	encodedBundle = base64.StdEncoding.EncodeToString(append([]byte(cert1[:40]), []byte(cert1[45:])...))
	out, err = parseCertificates(encodedBundle)
	assert.Error(t, err)

	// bad bundle
	encodedBundle = base64.StdEncoding.EncodeToString([]byte(cert1 + "\n " + cert2))
	out, err = parseCertificates(encodedBundle)
	assert.Error(t, err)

}

func TestCAAddAndRemove(t *testing.T) {

	cert1, err := generateRootX509CAForTest()
	assert.NoError(t, err)
	cert2, err := generateRootX509CAForTest()
	assert.NoError(t, err)
	certs := make(caCerts, 0)

	certs1, err := parseCertificates(base64.StdEncoding.EncodeToString([]byte(cert1)))
	assert.NoError(t, err)

	// add one cert
	assert.NoError(t, certs.add(certs1))
	assert.Len(t, certs, 1)
	decodedCert1, err := base64.StdEncoding.DecodeString(certs[0].Base64EncodedData)
	assert.NoError(t, err)
	assert.Equal(t, cert1, string(decodedCert1))

	// adding the same cert again should fail
	assert.Error(t, certs.add(certs1))

	certs2, err := parseCertificates(base64.StdEncoding.EncodeToString([]byte(cert2)))
	assert.NoError(t, err)
	// add the other cert
	assert.NoError(t, certs.add(certs2))
	assert.Len(t, certs, 2)
	decodedCert1, err = base64.StdEncoding.DecodeString(certs[0].Base64EncodedData)
	assert.NoError(t, err)
	decodedCert2, err := base64.StdEncoding.DecodeString(certs[1].Base64EncodedData)
	assert.NoError(t, err)
	assert.Equal(t, cert1, string(decodedCert1))
	assert.Equal(t, cert2, string(decodedCert2))

	// remove the first cert
	assert.NoError(t, certs.remove(certs1))
	assert.Len(t, certs, 1)
	decodedCert2, err = base64.StdEncoding.DecodeString(certs[0].Base64EncodedData)
	assert.NoError(t, err)
	assert.Equal(t, cert2, string(decodedCert2))

	// removing the fist cert again should fail
	assert.Error(t, certs.remove(certs1))

	// remove the first cert
	assert.NoError(t, certs.remove(certs2))
	assert.Len(t, certs, 0)
}
