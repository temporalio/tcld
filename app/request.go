package app

import (
	"context"

	"github.com/temporalio/tcld/protogen/api/requestservice/v1"
	"github.com/urfave/cli/v2"
)

type RequestClient struct {
	client requestservice.RequestServiceClient
	ctx    context.Context
}

type GetRequestClientFn func(ctx *cli.Context) (*RequestClient, error)

func GetRequestClient(ctx *cli.Context) (*RequestClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &RequestClient{
		client: requestservice.NewRequestServiceClient(conn),
		ctx:    ct,
	}, nil
}

func (c *RequestClient) getRequestStatus(namespace string, requestID string) error {
	res, err := c.client.GetRequestStatus(c.ctx, &requestservice.GetRequestStatusRequest{
		Namespace: namespace,
		RequestId: requestID,
	})
	if err != nil {
		return err
	}
	return PrintProto(res)
}

func NewRequestCommand(getRequestClientFn GetRequestClientFn) (CommandOut, error) {

	var c *RequestClient
	return CommandOut{Command: &cli.Command{
		Name:    "request",
		Usage:   "Manage asynchronous requests",
		Aliases: []string{"r"},
		Before: func(ctx *cli.Context) error {
			var err error
			c, err = getRequestClientFn(ctx)
			return err

		},
		Subcommands: []*cli.Command{{
			Name:    "get",
			Usage:   "Get the request status",
			Aliases: []string{"g"},
			Flags: []cli.Flag{
				NamespaceFlag,
				&cli.StringFlag{
					Name:     "request-id",
					Usage:    "The request-id of the asynchronous request",
					Aliases:  []string{"r"},
					Required: true,
				},
			},
			Action: func(ctx *cli.Context) error {
				return c.getRequestStatus(ctx.String(NamespaceFlagName), ctx.String("request-id"))
			},
		}},
	}}, nil
}
