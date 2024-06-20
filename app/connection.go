package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"regexp"

	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/temporalio/tcld/app/credentials/apikey"
	"github.com/temporalio/tcld/app/credentials/oauth"
)

const (
	VersionHeader                 = "tcld-version"
	CommitHeader                  = "tcld-commit"
	TemporalCloudAPIVersionHeader = "temporal-cloud-api-version"
	LegacyTemporalCloudAPIVersion = "2024-03-18-00"
	TemporalCloudAPIVersion       = "2024-05-13-00"
)

var (
	TemporalCloudAPIMethodRegex = regexp.MustCompile(`^\/temporal\.api\.cloud\.cloudservice\.v1\.CloudService\/[^\/]*$`)
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

	return ctx, conn, nil
}

func unaryVersionInterceptor(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	if TemporalCloudAPIMethodRegex.MatchString(method) {
		ctx = metadata.AppendToOutgoingContext(ctx, TemporalCloudAPIVersionHeader, TemporalCloudAPIVersion)
	} else {
		ctx = metadata.AppendToOutgoingContext(ctx, TemporalCloudAPIVersionHeader, LegacyTemporalCloudAPIVersion)
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

func defaultDialOptions(c *cli.Context, addr *url.URL) ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{
		grpc.WithUnaryInterceptor(unaryVersionInterceptor),
	}

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

	config, err := LoadTokenConfig(ctx)
	if err != nil {
		return nil, err
	}

	return oauth.NewCredential(
		config.TokenSource(),
		oauth.WithInsecureTransport(insecure),
	)
}
