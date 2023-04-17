package apikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"
)

const (
	IDHeader     = "tmprl-api-key-id"
	SecretHeader = "tmprl-api-secret-key"
	Separator    = "_"

	RequestSignatureHeader           = "tmprl-request-signature"
	RequestSignatureAlgorithmHeader  = "tmprl-request-signature-algorithm"
	RequestDatetimeHeader            = "tmprl-request-datetime"
	DefaultRequestSignatureAlgorithm = "tmprl-hmac-sha256"

	// requestSignatureFormat requires each of the following data on a newline
	// KeyID
	// RequestSignatureAlgorithm
	// RequestDatetime
	// ActionName
	requestSignatureFormat = "%s\n%s\n%s\n%s"
)

type Credential struct {
	ID                     string
	secret                 string // secret kept private to prevent accidental access.
	enableHMAC             bool
	allowInsecureTransport bool
}

type Option = func(c *Credential)

func WithHMAC(enable bool) Option {
	return func(c *Credential) {
		c.enableHMAC = enable
	}
}

func WithInsecureTransport(insecure bool) Option {
	return func(c *Credential) {
		c.allowInsecureTransport = insecure
	}
}

func NewCredential(key string, opts ...Option) (Credential, error) {
	if len(key) == 0 {
		return Credential{}, fmt.Errorf("an empty API key was provided")
	}

	s := strings.Split(key, Separator)
	if len(s) < 2 {
		return Credential{}, fmt.Errorf("an API key must be in the format of `{prefix}_{base62}_{base62]}`")
	}

	c := Credential{
		ID:     s[len(s)-2],
		secret: s[len(s)-1],
	}
	for _, opt := range opts {
		opt(&c)
	}

	return c, nil
}

func (c Credential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	ri, ok := credentials.RequestInfoFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve request info from context")
	}

	if !c.allowInsecureTransport {
		// Ensure the API key, AKA bearer token, is sent over a secure connection - meaning TLS.
		if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
			return nil, fmt.Errorf("the connection's transport security level is too low for API keys: %v", err)
		}
	}

	if c.enableHMAC {
		action, err := action(uri[0], ri.Method)
		if err != nil {
			return map[string]string{}, fmt.Errorf("failed to generate action for hmac: %v", err)
		}

		requestDatetime := time.Now().Format(time.RFC3339)
		msg := fmt.Sprintf(
			requestSignatureFormat,
			c.ID,
			DefaultRequestSignatureAlgorithm,
			requestDatetime,
			action,
		)

		h := hmac.New(sha256.New, []byte(c.secret))
		_, err = h.Write([]byte(msg))
		if err != nil {
			return map[string]string{}, fmt.Errorf("failed to generate hmac: %v", err)
		}

		return map[string]string{
			IDHeader:                        c.ID,
			RequestDatetimeHeader:           requestDatetime,
			RequestSignatureAlgorithmHeader: DefaultRequestSignatureAlgorithm,
			RequestSignatureHeader:          hex.EncodeToString(h.Sum(nil)),
		}, nil
	}

	return map[string]string{
		IDHeader:     c.ID,
		SecretHeader: c.secret,
	}, nil
}

func (c Credential) RequireTransportSecurity() bool {
	return !c.allowInsecureTransport
}

func action(rawURL, method string) (string, error) {
	url, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	parts := strings.Split(url.Hostname(), ".")

	return fmt.Sprintf("%s:%s", parts[0], path.Base(method)), nil
}

var _ credentials.PerRPCCredentials = (*Credential)(nil)
