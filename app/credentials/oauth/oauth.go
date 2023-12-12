package oauth

import (
	"context"
	"fmt"

	"github.com/temporalio/tcld/app/credentials"
	"golang.org/x/oauth2"
	grpccreds "google.golang.org/grpc/credentials"
)

type Option = func(c *Credential)

func WithInsecureTransport(insecure bool) Option {
	return func(c *Credential) {
		c.allowInsecureTransport = insecure
	}
}

type Credential struct {
	source                 oauth2.TokenSource
	allowInsecureTransport bool
}

func NewCredential(source oauth2.TokenSource, opts ...Option) (Credential, error) {
	if source == nil {
		return Credential{}, fmt.Errorf("a nil token source was provided")
	}

	c := Credential{
		source: source,
	}
	for _, opt := range opts {
		opt(&c)
	}

	return c, nil
}

func (c Credential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	ri, ok := grpccreds.RequestInfoFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve request info from context")
	}

	if !c.allowInsecureTransport {
		// Ensure the bearer token is sent over a secure connection - meaning TLS.
		if err := grpccreds.CheckSecurityLevel(ri.AuthInfo, grpccreds.PrivacyAndIntegrity); err != nil {
			return nil, fmt.Errorf("the connection's transport security level is too low for OAuth: %w", err)
		}
	}

	token, err := c.source.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve token from token source: %w", err)
	}

	return map[string]string{
		credentials.AuthorizationHeader: fmt.Sprintf("%s %s", token.Type(), token.AccessToken),
	}, nil
}

func (c Credential) RequireTransportSecurity() bool {
	return !c.allowInsecureTransport
}

var _ grpccreds.PerRPCCredentials = (*Credential)(nil)
