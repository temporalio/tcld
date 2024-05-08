package apikey

import (
	"context"
	"fmt"

	"github.com/temporalio/tcld/app/credentials"
	grpccreds "google.golang.org/grpc/credentials"
)

const (
	Separator = "_"
)

type Credential struct {
	Key                    string
	allowInsecureTransport bool
}

type Option = func(c *Credential)

func WithInsecureTransport(insecure bool) Option {
	return func(c *Credential) {
		c.allowInsecureTransport = insecure
	}
}

func NewCredential(key string, opts ...Option) (Credential, error) {
	if len(key) == 0 {
		return Credential{}, fmt.Errorf("an empty API key was provided")
	}

	c := Credential{
		Key: key,
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
		// Ensure the API key, AKA bearer token, is sent over a secure connection - meaning TLS.
		if err := grpccreds.CheckSecurityLevel(ri.AuthInfo, grpccreds.PrivacyAndIntegrity); err != nil {
			return nil, fmt.Errorf("the connection's transport security level is too low for API keys: %v", err)
		}
	}

	return map[string]string{
		credentials.AuthorizationHeader: fmt.Sprintf("%s %s", credentials.AuthorizationBearer, c.Key),
	}, nil
}

func (c Credential) RequireTransportSecurity() bool {
	return !c.allowInsecureTransport
}

var _ grpccreds.PerRPCCredentials = (*Credential)(nil)
