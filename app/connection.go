package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func GetServerConnection(c *cli.Context, opts ...grpc.DialOption) (context.Context, *grpc.ClientConn, error) {

	serverAddr := c.String(ServerFlagName)
	var credentialOption grpc.DialOption
	parts := strings.Split(serverAddr, ":")

	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("unable to parse hostname: %s", serverAddr)
	}

	hostname := parts[0]
	switch hostname {
	case "localhost":
		credentialOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	default:
		credentialOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: hostname,
		}))
	}
	conn, err := grpc.Dial(
		serverAddr,
		append(opts, credentialOption)...,
	)
	if err != nil {
		return nil, nil, err
	}
	tokens, err := loadLoginConfig(c)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()

	ctx = metadata.AppendToOutgoingContext(ctx, "tcld-version", getVersion())
	ctx = metadata.AppendToOutgoingContext(ctx, "tcld-commit", Commit)

	if len(tokens.AccessToken) > 0 {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tokens.AccessToken)
	}
	return ctx, conn, nil
}
