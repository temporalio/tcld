package app

import (
	"context"

	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"

	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/namespace/v1"
)

type (
	MigrationClient struct {
		client cloudservice.CloudServiceClient
		ctx    context.Context
	}
	GetMigrationClientFn func(ctx *cli.Context) (*MigrationClient, error)
)

func NewMigrationClient(ctx context.Context, conn *grpc.ClientConn) *MigrationClient {
	return &MigrationClient{
		client: cloudservice.NewCloudServiceClient(conn),
		ctx:    ctx,
	}
}

func GetMigrationClient(ctx *cli.Context) (*MigrationClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return NewMigrationClient(ct, conn), nil
}

func (c *MigrationClient) getMigration(migrationId string) (*namespace.Migration, error) {
	resp, err := c.client.GetMigration(c.ctx, &cloudservice.GetMigrationRequest{
		MigrationId: migrationId,
	})
	if err != nil {
		return nil, err
	}
	return resp.Migration, nil
}

func (c *MigrationClient) listMigrations() error {
	totalRes := &cloudservice.GetMigrationsResponse{}
	pageToken := ""
	for {
		resp, err := c.client.GetMigrations(c.ctx, &cloudservice.GetMigrationsRequest{
			PageToken: pageToken,
		})
		if err != nil {
			return err
		}
		totalRes.Migrations = append(totalRes.Migrations, resp.Migrations...)
		pageToken = resp.NextPageToken
		if len(pageToken) == 0 {
			return PrintProto(totalRes)
		}
	}
}

func (c *MigrationClient) startMigration(requestId, migrationEndpointId, sourceNamespace, targetNamespace string) error {
	resp, err := c.client.StartMigration(c.ctx, &cloudservice.StartMigrationRequest{
		Spec: &namespace.MigrationSpec{
			MigrationEndpointId: migrationEndpointId,
			Spec: &namespace.MigrationSpec_ToCloudSpec{
				ToCloudSpec: &namespace.MigrationToCloudSpec{
					SourceNamespace: sourceNamespace,
					TargetNamespace: targetNamespace,
				},
			},
		},
		AsyncOperationId: requestId,
	})
	if err != nil {
		return err
	}
	return PrintProto(resp)
}

func (c *MigrationClient) migrationHandover(requestId, migrationId, replicaId string) error {
	resp, err := c.client.HandoverNamespace(c.ctx, &cloudservice.HandoverNamespaceRequest{
		MigrationId:      migrationId,
		ToReplicaId:      replicaId,
		AsyncOperationId: requestId,
	})
	if err != nil {
		return err
	}
	return PrintProto(resp)
}

func (c *MigrationClient) confirmMigration(requestId, migrationId string) error {
	resp, err := c.client.ConfirmMigration(c.ctx, &cloudservice.ConfirmMigrationRequest{
		MigrationId:      migrationId,
		AsyncOperationId: requestId,
	})
	if err != nil {
		return err
	}
	return PrintProto(resp)
}

func (c *MigrationClient) abortMigration(requestId, migrationId string) error {
	resp, err := c.client.AbortMigration(c.ctx, &cloudservice.AbortMigrationRequest{
		MigrationId:      migrationId,
		AsyncOperationId: requestId,
	})
	if err != nil {
		return err
	}
	return PrintProto(resp)
}

func NewMigrationCommand(getMigrationClient GetMigrationClientFn) (CommandOut, error) {
	var c *MigrationClient
	migrationIdFlag := &cli.StringFlag{
		Name:     "id",
		Aliases:  []string{"i"},
		Usage:    "Migration id",
		Required: true,
	}
	migrationEndpointIdFlag := &cli.StringFlag{
		Name:     "endpoint-id",
		Aliases:  []string{"e"},
		Usage:    "Migration endpoint id",
		Required: true,
	}
	sourceNamespaceFlag := &cli.StringFlag{
		Name:     "source-namespace",
		Aliases:  []string{"s"},
		Usage:    "Source namespace name",
		Required: true,
	}
	targetNamespaceFlag := &cli.StringFlag{
		Name:     "target-namespace",
		Aliases:  []string{"t"},
		Usage:    "Target namespace name",
		Required: true,
	}
	toReplicaIdFlag := &cli.StringFlag{
		Name:     "to-replica-id",
		Aliases:  []string{"rp"},
		Usage:    "The id of the replica to make active",
		Required: true,
	}

	return CommandOut{
		Command: &cli.Command{
			Name:    "migration",
			Aliases: []string{"m"},
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getMigrationClient(ctx)
				return err
			},
			Usage: "(private preview) Manage migrations between self-hosted Temporal and Temporal cloud",
			Subcommands: []*cli.Command{
				{
					Name:    "get",
					Aliases: []string{"g"},
					Usage:   "Get a migration",
					Flags: []cli.Flag{
						migrationIdFlag,
					},
					Action: func(ctx *cli.Context) error {
						id := ctx.String(migrationIdFlag.Name)
						m, err := c.getMigration(id)
						if err != nil {
							return err
						}
						return PrintProto(m)
					},
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List migrations",
					Flags:   []cli.Flag{},
					Action: func(ctx *cli.Context) error {
						return c.listMigrations()
					},
				},
				{
					Name:    "start",
					Aliases: []string{"s"},
					Usage:   "Start a new migration",
					Flags: []cli.Flag{
						RequestIDFlag,
						migrationEndpointIdFlag,
						sourceNamespaceFlag,
						targetNamespaceFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.startMigration(
							ctx.String(RequestIDFlag.Name),
							ctx.String(migrationEndpointIdFlag.Name),
							ctx.String(sourceNamespaceFlag.Name),
							ctx.String(targetNamespaceFlag.Name),
						)
					},
				},
				{
					Name:    "handover",
					Aliases: []string{"s"},
					Usage:   "Handover the namespace from on-prem to cloud, or from cloud back to on-prem",
					Flags: []cli.Flag{
						RequestIDFlag,
						migrationIdFlag,
						toReplicaIdFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.migrationHandover(
							ctx.String(RequestIDFlag.Name),
							ctx.String(migrationIdFlag.Name),
							ctx.String(toReplicaIdFlag.Name),
						)
					},
				},
				{
					Name:    "confirm",
					Aliases: []string{"c"},
					Usage:   "Confirm the migration",
					Flags: []cli.Flag{
						RequestIDFlag,
						migrationIdFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.confirmMigration(
							ctx.String(RequestIDFlag.Name),
							ctx.String(migrationIdFlag.Name),
						)
					},
				},
				{
					Name:    "abort",
					Aliases: []string{"a"},
					Usage:   "Abort the migration",
					Flags: []cli.Flag{
						RequestIDFlag,
						migrationIdFlag,
					},
					Action: func(ctx *cli.Context) error {
						return c.abortMigration(
							ctx.String(RequestIDFlag.Name),
							ctx.String(migrationIdFlag.Name),
						)
					},
				},
			},
		},
	}, nil
}
