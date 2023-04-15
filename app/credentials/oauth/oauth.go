package oauth

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials"
)

const (
	Header = "authorization"
)

var _ credentials.PerRPCCredentials = (*Credential)(nil)

type Option = func(c *Credential)

func WithInsecure(insecure bool) Option {
	return func(c *Credential) {
		c.insecure = insecure
	}
}

type Credential struct {
	accessToken string // keep unexported to prevent accidental leakage of the token.
	insecure    bool
}

func NewCredential(accessToken string, opts ...Option) (Credential, error) {
	if len(accessToken) == 0 {
		return Credential{}, fmt.Errorf("an empty access token was provided")
	}

	c := Credential{
		accessToken: accessToken,
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

	if !c.insecure {
		// Ensure the bearer token is sent over a secure connection - meaning TLS.
		if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
			return nil, fmt.Errorf("the connection's transport security level is too low for OAuth: %v", err)
		}
	}

	return map[string]string{
		Header: c.token(),
	}, nil
}

func (c Credential) RequireTransportSecurity() bool {
	return !c.insecure
}

func (c Credential) token() string {
	return "Bearer " + c.accessToken
}
