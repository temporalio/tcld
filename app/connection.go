package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"regexp"
	"time"

	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	LegacyTemporalCloudAPIVersion = "2025-07-09-00"
	TemporalCloudAPIVersion       = "v9999.0.0"
	userAgentTemplate             = "tcld/%s"
)

var (
	TemporalCloudAPIMethodRegex = regexp.MustCompile(`^\/temporal\.api\.cloud\.cloudservice\.v1\.CloudService\/[^\/]*$`)

	// UserAgent is set on package initialization.
	UserAgent string
)

func init() {
	buildInfo := NewBuildInfo()
	UserAgent = fmt.Sprintf(userAgentTemplate, buildInfo.Version)
}

func GetServerConnection(c *cli.Context, opts ...grpc.DialOption) (context.Context, *grpc.ClientConn, error) {
	addr, err := url.Parse(c.String(ServerFlagName))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse server address: %s", err)
	}

	defaultOpts, err := defaultDialOptions(c, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate default dial options: %s", err)
	}

	conn, err := grpc.Dial( //nolint:all this is supported for now, ignore deprecation
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
	retryOpts := []grpcretry.CallOption{
		grpcretry.WithBackoff(grpcretry.BackoffExponentialWithJitter(250*time.Millisecond, 0.1)),
		grpcretry.WithMax(5),
		grpcretry.WithCodes(codes.Unavailable, codes.ResourceExhausted),
	}

	opts := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(
			unaryVersionInterceptor,
			grpcretry.UnaryClientInterceptor(retryOpts...),
		),
		grpc.WithUserAgent(UserAgent),
	}

	creds, err := newRPCCredential(c)
	if err != nil {
		return []grpc.DialOption{}, err
	} else if creds != nil {
		opts = append(opts, grpc.WithPerRPCCredentials(creds))
	}

	serverName := addr.Hostname()
	if tlsServerName := c.String(TLSServerNameFlagName); tlsServerName != "" {
		serverName = tlsServerName
	}
	transport := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
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
