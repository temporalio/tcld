package app

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	cert1 = `-----BEGIN CERTIFICATE-----
MIIFGjCCAwKgAwIBAgIUMykW2d1LvLnP/CLarSWgK9rMJcswDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UECgwIVGVtcG9yYWwwHhcNMjIwMjIyMjA0NzIzWhcNMjMwMjIy
MjA0NzIzWjATMREwDwYDVQQKDAhUZW1wb3JhbDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAL4q2lUz54yzjEL8M4hfdcjjb8SHzDEOmyIiX6XrXFV7OVfj
iCpiysVfJrnO2Trkb0z/wBNXlYGQNpnuxqpoq3G4m/gNHY7QupLRExJs24vdwnwS
EbE+CX/bWaJGsO0Yg3WvXvr6bXEoysKiipzmK5eoKpl9p1Gf5Pb7FLKBwdSjI4Jp
qBGJ6AQ6bhiqkbw2A90Ter4/d8SUObLanPsNz6rePGn81J8ZwDL2HubJA98bsN+g
/ZOGL9v/VY7N3uIJYT48SwPLtaYdlnjyibIObjxUhrq9KDAh2HnazBssU8pIz1Wu
ibUf3jbs8bVdn8b8pxfhlV2AtKniHtpyI4p7L1xGLOkJsnZYQC2Le5NoQ0mPmvkZ
up5tZIrRsBnny8OO/OcnP7xP4dAtJWeu7IsXY7+smgf939/ZJPCj5canBqR9QsKj
/POTS6cTfCMf+QrM7fZMJ/khNNhnf+IsVSYwbXM5sklpDi0PI5W6h9XmhM1/L43/
P65U7FixSO3iZYEt7lX+RwrPlMYhBeTnGuxbgYldMPTv68ccD7tfkgtRgy0AZN09
m0yBvFC5649mq8f1sFrvoX4f0Y/7VYkfW7WHJ9PW+bLAAj40X+rbd/JU/3TR8S3n
J3h9GsBd82WBGBEmoYaAe8JA9rkieLuri84xt3CljABEK5YCI7uj/Eh3wgrJAgMB
AAGjZjBkMB0GA1UdDgQWBBSKEZAUR58YJcaN/VJiIgOZgBdfTTAfBgNVHSMEGDAW
gBSKEZAUR58YJcaN/VJiIgOZgBdfTTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud
DwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAt/1uHdM6oDK9KBsaXvz7up/+
l4MdXCqZ8JLfWGcokEZ+QK4ocRkdv/bS85NuuNQel5qnFTU1QKrbF4voCky3ty/l
blUbyqHm2Bjq6tqdzkwupU9HQItDjkTAnAV5AerfuMYdgqxdYSSKzto2GGMDgog4
gSy8gwSvLF7lp4cn1HGWAdA0cJA0jSw6v5FcvicHMlzWN3itpINaUborndpfMij5
FiGf6QfJtM1hZrhUbgOC14U8Dgd5KQB5FOIoSf5hQH1UWP2fEqAFAHcAR1r3LVCh
NkuCRzKWzusTHHf1S7iHcd4/xPqFvuSxtXqOi3X7c9/T5vvmPOTNISqTR2RJ0Qox
9etkSsKZi2KrlgmPLpELLxuNs4k5PC51FmAu5FX5brr3njGRuInrje4nX7Q1MDGo
n+eVIf+pwQAZF5EglDwYtdawftXToor3VWxk/JpyCP3BHtFoFVqOnZNxJ02ElMpr
DOtAGtke52aRbnqKXT3SSQxhcK+FVtXCiM3G3R7X6dfGQNDkHhaGhzNvVEhOHBq+
8KdxougDTJRZDtAPfN/vYHW1Jhn+fmdym/tvlLU55WvC0DwQYb9573Rj+IVNNIEy
XzuS1azBP89djxYQiBADn9fFMkDx4qSBNQWZbwJ9aF/HHmet70Y29EhCsiyJWN7s
Ben+2JbIksdEkquUEsw=
-----END CERTIFICATE-----`

	cert2 = `-----BEGIN CERTIFICATE-----
MIIFGjCCAwKgAwIBAgIUPzujhegPjbzdDuhf3VCPT/q2s7gwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UECgwIVGVtcG9yYWwwHhcNMjIwNDAxMjIzOTEwWhcNMjMwNDAx
MjIzOTEwWjATMREwDwYDVQQKDAhUZW1wb3JhbDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAN56r2viIYBvE18jzUeWvdmHYPqKHWYKhkXiET4ID6EL7lKw
AvA+rgOxcpfJAinjsTR7/EJW4q4sn3xZ9zqNsPG/WBLGFRX0o+IxWp8kbCwecUfa
JcnqJ+XvL+nz9xPr2ie3dtnyW1OIbrioGNCjTLKBZo97rRRRMwtRVqRZqcacVXtQ
sJjzvOhT3dhs/aFRJFAjmX834JcnN7R21ovSKCcS6j7uXc9uCVkG1gGtoMOtYOUT
UAHAUwsy2+0LdZ4gRbBugvwDs2IBul0N8a2OVWl18NyFvYhH44m3AZDpAzEYMse6
vCPRJuodUuPpTxQ7SWGicEP/V39yzaqF9sUT5Sf9xWKVUEFzQ4NPXWXvq2ZqjiG1
qbkkPB1Xe0AKv293t3NES0J0oHED1IIEqlNdVJhOZ3dni2CqsJwzkAQfqvbCyZa+
esL3Wm1XNJIHEn1PLmt3AEmIn1Qhcumrh/VVfzPc0ObvRrYY6vWcPi1j1ay6RsZt
UoWJI61dYrMsaG+KU/9LYt7m9fqI7/NiKxy/nFvDrVafsywPeehtf6JW40rqJ1ve
QE7FxWWdam2ycZXzHm0LSodc+rJ51fSTkSCXK1mfXLLL/M5ZociLV8wblx5ok02A
1pMYkuhJVNG3blO4ZEyImCe5J6o9YmqNPsPMPJpmEgW7tbfXdxWPNHIq1x/HAgMB
AAGjZjBkMB0GA1UdDgQWBBRjP0OjIb5rbmsrLRHV0unbCOpzlDAfBgNVHSMEGDAW
gBRjP0OjIb5rbmsrLRHV0unbCOpzlDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud
DwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAzi7vV06RJxqaiPYFJTBbiXXV
taqGauN21sbGgu4fm+rcfpNMVTM/lg0MixGxQf9SrU6ryBom6mqK9B5MfdaH1H5t
clMBI6Qnug61Y4DSUSIoquvwMM4Gllhvv00Jfzq+4vMV9AD/rhcjbyAWcCa69p0J
W+wRwtB6k740403fjC8Gol+McqHnJg5HtWnDEc3I1kdBoBcgtBuU/2OdT0+Xfsqi
3BoDnhPa2cizOvP3Fz/5+k/IzfL6kEqj1mOk6b4qdKbpMuh5R8Ry9vxyggC9IPPy
VBiSPihuUWzrS7jAyA7dtXS3lxmog3nNki3fq/NuO/F5jr5Gm4QNKAyFl8LjAiYI
2zpZV+j30rnQ6bs9LqrSxZYNGCWZCJyzLHD6CTj58HuG8XLEZCmhfAJGQ8vhibpJ
FveB7CEbzv5hYTu4A75GvgfgzP/sw3RzUKX8+Eyzhfg9hp71jBgpBqLw/zvV3neu
OSPmEyr16SUajkUX2DoDpTIHq9we6fDf4QA2Vjk1C2duqXWRoXpHwhOMqhJOmhVR
EbyEybwMJYpHBM+d8gUNjorfpOYCZzFq8TGRgUAN/K+ZRuXdFzOGCd4P1oBEfMTU
ZqvwI850zF4LD8LOxj0W1VnXJASS+RTa4sF1x9t5ojvxpFBkO4nO/5tHqqWPtyKI
dHL8e8XETZi/ZC6LIeo=
-----END CERTIFICATE-----`
)

func TestCABundleParser(t *testing.T) {

	// invalid base64 encoded data
	_, err := parseCertificates("temporal cloud not base 64 encoded")
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
