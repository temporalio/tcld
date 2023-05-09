package app

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCAGenerate(t *testing.T) {

	_, _, err := generateCACertificate(generateCACertificateInput{})
	assert.Error(t, err)

	caPem, caPrivKeyPem, err := generateCACertificate(generateCACertificateInput{
		Organization: "testtemporal",
		Duration:     365 * 24 * time.Hour,
	})
	assert.NoError(t, err)

	fmt.Println("caPEM: ", caPem)
	fmt.Println("caPrivKeyPem: ", caPrivKeyPem)
}
