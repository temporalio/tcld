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
	VersionHeader                 = "tcld-version"
	CommitHeader                  = "tcld-commit"
	TemporalCloudAPIVersionHeader = "temporal-cloud-api-version"
	TemporalCloudAPIVersion       = "2023-07-26-01"
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

	buildInfo := NewBuildInfo()

	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, VersionHeader, buildInfo.Version)
	ctx = metadata.AppendToOutgoingContext(ctx, CommitHeader, buildInfo.Commit)
	ctx = metadata.AppendToOutgoingContext(ctx, TemporalCloudAPIVersionHeader, TemporalCloudAPIVersion)

	return ctx, conn, nil
}

func defaultDialOptions(c *cli.Context, addr *url.URL) ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	creds, err := newRPCCredential(c)
	if err != nil {
		return []grpc.DialOption{}, err
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

	// Set max message size to 50MB. Messages should never be this large, but useful in a pinch.
	maxMsgSize := 50 * 1000 * 1000
	opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize), grpc.MaxCallSendMsgSize(maxMsgSize)))

	return opts, nil
}

func newRPCCredential(ctx *cli.Context) (credentials.PerRPCCredentials, error) {
	insecure := ctx.Bool(InsecureConnectionFlagName)

	apiKey := ctx.String(APIKeyFlagName)
	if len(apiKey) > 0 {
		return apikey.NewCredential(
			apiKey,
			apikey.WithInsecureTransport(insecure),
		)
	}

	config, err := ensureLogin(ctx)
	if err != nil {
		return nil, err
	}

	return oauth.NewCredential(
		config.TokenSource(),
		oauth.WithInsecureTransport(insecure),
	)
}
