package app

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

type caCert struct {
	Fingerprint       string    `json:"fingerprint"`
	Issuer            string    `json:"issuer"`
	Subject           string    `json:"subject"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	Base64EncodedData string    `json:"base64EncodedData"`
}

type caCerts []caCert

func parseCertificates(encodedCerts string) (caCerts, error) {

	// decode the cert bundle
	bundle, err := base64.StdEncoding.DecodeString(encodedCerts)
	if err != nil {
		return nil, err
	}
	if len(bundle) == 0 {
		return caCerts{}, nil
	}

	certBlocks := [][]byte{}
	var blocks []byte
	p := bundle
	for {
		var block *pem.Block
		var rem []byte
		block, rem = pem.Decode(p)
		if block == nil {
			break
		}
		blocks = append(blocks, block.Bytes...)
		certBlocks = append(certBlocks, []byte(strings.TrimSpace(string(p[:len(p)-len(rem)]))))
		p = rem
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("failed to decode certificates")
	}
	// If p is greater than 0, then this means that there was a portion of the certificate that
	// is/was malformed.
	if len(p) > 0 {
		return nil, fmt.Errorf("failed to parse one or more certificates, remainingBytesLen=%d", len(p))
	}
	certs, err := x509.ParseCertificates(blocks)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates: %s", err.Error())
	}
	out := make(caCerts, len(certs))
	for i := range certs {
		sum := sha1.Sum(certs[i].Raw)
		out[i].Fingerprint = strings.ToLower(hex.EncodeToString(sum[:]))
		out[i].Base64EncodedData = base64.StdEncoding.EncodeToString(certBlocks[i])
		out[i].Issuer = certs[i].Issuer.String()
		out[i].Subject = certs[i].Subject.String()
		out[i].NotBefore = certs[i].NotBefore
		out[i].NotAfter = certs[i].NotAfter
	}
	return out, nil
}

func (c *caCerts) bundle() (string, error) {
	out := make([]byte, 0)
	for i := range *c {
		decodedCert, err := base64.StdEncoding.DecodeString((*c)[i].Base64EncodedData)
		if err != nil {
			return "", fmt.Errorf("failed to base64 decode cert: %s", err.Error())
		}
		if len(out) != 0 {
			out = append(out, []byte("\n")...)
		}
		out = append(out, decodedCert...)
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

func (c *caCerts) add(certs caCerts) error {

	for i := range certs {
		for j := range *c {
			if certs[i].Fingerprint == (*c)[j].Fingerprint {
				return fmt.Errorf("certificate with fingerprint '%s' already exists", (*c)[j].Fingerprint)
			}
		}
	}
	*c = append(*c, certs...)
	return nil
}

func (c *caCerts) remove(certs caCerts) error {

	for i := range certs {
		for j := range *c {
			if certs[i].Fingerprint == (*c)[j].Fingerprint {
				*c = append((*c)[:j], (*c)[j+1:]...)
				break
			}
			if j == len(*c)-1 {
				return fmt.Errorf("certificate with fingerprint '%s' does not exists", certs[i].Fingerprint)
			}
		}
	}
	return nil
}
