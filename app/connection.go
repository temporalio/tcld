package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"

	"github.com/temporalio/tcld/app/credentials/apikey"
	"github.com/temporalio/tcld/app/credentials/oauth"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	VersionHeader = "tcld-version"
	CommitHeader  = "tcld-commit"
)

func GetServerConnection(c *cli.Context, opts ...grpc.DialOption) (context.Context, *grpc.ClientConn, error) {
	addr, err := url.Parse(c.String(ServerFlagName))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse server address: %s", err)
	}

	defaultOpts, err := defaultDialOptions(c, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate default dial options: %s", err)
	}

	conn, err := grpc.Dial(
		addr.String(),
		append(defaultOpts, opts...)...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial `%s`: %v", addr.String(), err)
	}
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, VersionHeader, getVersion())
	ctx = metadata.AppendToOutgoingContext(ctx, CommitHeader, Commit)

	return ctx, conn, nil
}

func defaultDialOptions(c *cli.Context, addr *url.URL) ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	creds, err := newRPCCredential(c)
	if err != nil {
		return []grpc.DialOption{}, nil
	} else if creds != nil {
		opts = append(opts, grpc.WithPerRPCCredentials(creds))
	}

	transport := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: addr.Hostname(),
	})
	if c.Bool(InsecureConnectionFlagName) {
		transport = insecure.NewCredentials()
	}
	opts = append(opts, grpc.WithTransportCredentials(transport))

	return opts, nil
}

func newRPCCredential(c *cli.Context) (credentials.PerRPCCredentials, error) {
	insecure := c.Bool(InsecureConnectionFlagName)

	apiKey := c.String(APIKeyFlagName)
	if len(apiKey) > 0 {
		return apikey.NewCredential(
			apiKey,
			apikey.WithHMAC(c.Bool(EnableHMACFlagName)),
			apikey.WithInsecure(insecure),
		)
	}

	tokens, err := loadLoginConfig(c)
	if err != nil {
		return nil, err
	}

	if len(tokens.AccessToken) > 0 {
		return oauth.NewCredential(
			tokens.AccessToken,
			oauth.WithInsecure(insecure),
		)
	}

	// Use no credentials for this connection.
	return nil, nil
}
