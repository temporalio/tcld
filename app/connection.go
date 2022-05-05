package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func GetServerConnection(c *cli.Context) (context.Context, *grpc.ClientConn, error) {

	serverAddr := c.String(ServerFlagName)
	var option grpc.DialOption
	parts := strings.Split(serverAddr, ":")

	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("unable to parse hostname: %s", serverAddr)
	}

	hostname := parts[0]
	switch hostname {
	case "localhost":
		option = grpc.WithInsecure()
	default:
		option = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName: hostname,
		}))
	}
	conn, err := grpc.Dial(
		serverAddr,
		option,
	)
	if err != nil {
		return nil, nil, err
	}
	tokens, err := loadLoginConfig(c)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()

	ctx = metadata.AppendToOutgoingContext(ctx, "tcld-version", Version)
	ctx = metadata.AppendToOutgoingContext(ctx, "tcld-commit", Commit)

	if len(tokens.AccessToken) > 0 {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tokens.AccessToken)
	}
	return ctx, conn, nil
}
