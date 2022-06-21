package app

import (
	"context"
	"fmt"
	"time"

	"github.com/gosuri/uilive"
	"github.com/temporalio/tcld/api/temporalcloudapi/request/v1"
	"github.com/temporalio/tcld/api/temporalcloudapi/requestservice/v1"
	"github.com/urfave/cli/v2"
)

const (
	AsyncRequestFlagName   = "async"
	RequestTimeoutFlagName = "request-timeout"
)

var (
	RequestTimeoutFlag = &cli.DurationFlag{
		Name:    RequestTimeoutFlagName,
		Usage:   "Time to wait for asynchronous requests to finish",
		EnvVars: []string{"REQUEST_TIMEOUT"},
		Aliases: []string{"rt"},
		Value:   time.Hour,
	}
	AsyncRequestFlag = &cli.BoolFlag{
		Name:    AsyncRequestFlagName,
		Usage:   "Do not block on asynchronous requests",
		Aliases: []string{"a"},
		EnvVars: []string{"ASYNC_REQUEST"},
	}
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

func (c *RequestClient) getRequestStatus(ctx *cli.Context, requestID string) (*request.RequestStatus, error) {
	res, err := c.client.GetRequestStatus(c.ctx, &requestservice.GetRequestStatusRequest{
		Namespace: ctx.String(NamespaceFlagName),
		RequestId: requestID,
	})
	if err != nil {
		return nil, err
	}
	return res.RequestStatus, nil
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
				res, err := c.getRequestStatus(ctx, ctx.String("request-id"))
				if err != nil {
					return err
				}
				return PrintProto(res)
			},
		}, {
			Name:    "wait",
			Usage:   "wait till the request completes",
			Aliases: []string{"w"},
			Flags: []cli.Flag{
				NamespaceFlag,
				&cli.StringFlag{
					Name:     "request-id",
					Usage:    "the request-id of the asynchronous request",
					Aliases:  []string{"r"},
					Required: true,
				},
			},
			Action: func(ctx *cli.Context) error {
				return c.waitOnRequest(ctx, "", ctx.String("request-id"))
			},
		}},
	}}, nil
}

func (c *RequestClient) waitOnRequest(ctx *cli.Context, operation string, requestID string) error {

	ticker := time.NewTicker(time.Millisecond)
	timer := time.NewTimer(ctx.Duration(RequestTimeoutFlagName))

	writer := uilive.New()
	writer.Start()
	defer writer.Stop()

loop:
	for {
		select {
		case <-timer.C:
			return fmt.Errorf("timed out waiting for request to complete, namespace=%s, requestID=%s, timeout=%s",
				ctx.String(NamespaceFlagName),
				requestID,
				ctx.Duration(RequestTimeoutFlagName),
			)
		case <-ticker.C:
			status, err := c.getRequestStatus(ctx, requestID)
			if err != nil {
				return err
			}
			switch status.State {
			case request.STATE_FULFILLED:
				break loop
			case request.STATE_FAILED:
				fmt.Fprintf(writer, "operation failed \n")
				return fmt.Errorf("request failed: %s", status.FailureReason)
			case request.STATE_CANCELLED:
				fmt.Fprintf(writer, "operation failed \n")
				return fmt.Errorf("request was cancelled: %s", status.FailureReason)
			}
			if operation != "" {
				fmt.Fprintf(writer, "waiting for %s operation (requestId='%s') to finish, current state: %s\n",
					operation, requestID, request.RequestStatus_State_name[int32(status.State)])
			} else {
				fmt.Fprintf(writer, "waiting for request with '%s' id to finish, current state: %s\n",
					requestID, request.RequestStatus_State_name[int32(status.State)])
			}
			ticker.Reset(time.Second * time.Duration(status.CheckDuration.Seconds))
		}
	}
	if operation != "" {
		fmt.Fprintf(writer, "%s operation completed successfully\n", operation)
	} else {
		fmt.Fprintf(writer, "request with '%s' id to finished successfully\n", requestID)
	}
	return nil
}

func (c *RequestClient) HandleRequestStatus(
	ctx *cli.Context,
	operation string,
	status *request.RequestStatus,
) error {
	if err := PrintProto(status); err != nil {
		return err
	}
	if !ctx.Bool(AsyncRequestFlagName) {
		return c.waitOnRequest(ctx, operation, status.RequestId)
	}
	return nil
}
