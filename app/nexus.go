package app

import (
	"context"
	"fmt"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/nexus/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/operation/v1"
	"github.com/urfave/cli/v2"
)

type (
	NexusClient struct {
		client cloudservice.CloudServiceClient
		ctx    context.Context
	}
	GetNexusClientFn func(ctx *cli.Context) (*NexusClient, error)
)

func GetNexusClient(ctx *cli.Context) (*NexusClient, error) {
	ct, conn, err := GetServerConnection(ctx)
	if err != nil {
		return nil, err
	}
	return &NexusClient{
		client: cloudservice.NewCloudServiceClient(conn),
		ctx:    ct,
	}, nil
}

func (c *NexusClient) getEndpointByName(endpointName string) (*nexus.Endpoint, error) {
	endpoints, err := c.listEndpoints(endpointName)
	if err != nil {
		return nil, err
	}
	if len(endpoints) > 1 {
		return nil, fmt.Errorf("more than 1 endpoint found with the same name. This should not happen")
	}
	if len(endpoints) > 0 {
		return endpoints[0], nil
	}
	return nil, fmt.Errorf("endpoint not found") // TODO: if id is used, get might throw NotFound differently. make consistent.
}

func (c *NexusClient) listEndpoints(endpointName string) ([]*nexus.Endpoint, error) {
	endpoints := make([]*nexus.Endpoint, 0)
	pageToken := ""
	for {
		resp, err := c.client.GetNexusEndpoints(c.ctx, &cloudservice.GetNexusEndpointsRequest{
			Name:      endpointName,
			PageToken: pageToken,
		})
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, resp.Endpoints...)
		pageToken = resp.NextPageToken
		if len(pageToken) == 0 {
			return endpoints, nil
		}
	}
}

func (c *NexusClient) createEndpoint(
	endpointName string,
	targetNamespaceID string,
	targetTaskQueue string,
	allowedNamespaceIDs []string,
	asyncOperationId string,
) (*cloudservice.CreateNexusEndpointResponse, error) {
	policySpecs := make([]*nexus.EndpointPolicySpec, len(allowedNamespaceIDs))
	for i, ns := range allowedNamespaceIDs {
		policySpecs[i] = &nexus.EndpointPolicySpec{
			AllowedCloudNamespacePolicySpec: &nexus.AllowedCloudNamespacePolicySpec{
				NamespaceId: ns,
			},
		}
	}
	resp, err := c.client.CreateNexusEndpoint(c.ctx, &cloudservice.CreateNexusEndpointRequest{
		Spec: &nexus.EndpointSpec{
			Name: endpointName,
			TargetSpec: &nexus.EndpointTargetSpec{
				WorkerTargetSpec: &nexus.WorkerTargetSpec{
					NamespaceId: targetNamespaceID,
					TaskQueue:   targetTaskQueue,
				},
			},
			PolicySpecs: policySpecs,
		},
		AsyncOperationId: asyncOperationId,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *NexusClient) patchEndpoint(
	existingEndpoint *nexus.Endpoint,
	targetNamespaceID string,
	targetTaskQueue string,
	resourceVersion string,
	asyncOperationId string,
) (*operation.AsyncOperation, error) {
	if targetNamespaceID != "" {
		existingEndpoint.Spec.TargetSpec.WorkerTargetSpec.NamespaceId = targetNamespaceID
	}
	if targetTaskQueue != "" {
		existingEndpoint.Spec.TargetSpec.WorkerTargetSpec.TaskQueue = targetTaskQueue
	}

	return c.callUpdateEndpoint(existingEndpoint, resourceVersion, asyncOperationId)
}

func (c *NexusClient) callUpdateEndpoint(
	modifiedEndpoint *nexus.Endpoint,
	resourceVersion string,
	asyncOperationId string,
) (*operation.AsyncOperation, error) {
	resp, err := c.client.UpdateNexusEndpoint(c.ctx, &cloudservice.UpdateNexusEndpointRequest{
		EndpointId:       modifiedEndpoint.Id,
		Spec:             modifiedEndpoint.Spec,
		ResourceVersion:  resourceVersion,
		AsyncOperationId: asyncOperationId,
	})
	if err != nil {
		return nil, err
	}
	return resp.AsyncOperation, nil
}

func (c *NexusClient) addAllowedNamespaces(
	existingEndpoint *nexus.Endpoint,
	namespaceIDs []string,
	resourceVersion string,
	asyncOperationId string,
) (*operation.AsyncOperation, error) {
	existingPolicySpecs := existingEndpoint.Spec.PolicySpecs
	existingAllowedNamespaceIDMap := make(map[string]struct{}, len(existingPolicySpecs))
	for _, policySpec := range existingPolicySpecs {
		existingAllowedNamespaceIDMap[policySpec.AllowedCloudNamespacePolicySpec.NamespaceId] = struct{}{}
	}

	updatedPolicySpecs := make([]*nexus.EndpointPolicySpec, len(existingPolicySpecs))
	copy(updatedPolicySpecs, existingPolicySpecs)
	hasChange := false
	for _, namespaceID := range namespaceIDs {
		if _, ok := existingAllowedNamespaceIDMap[namespaceID]; !ok {
			hasChange = true
			updatedPolicySpecs = append(updatedPolicySpecs, &nexus.EndpointPolicySpec{
				AllowedCloudNamespacePolicySpec: &nexus.AllowedCloudNamespacePolicySpec{
					NamespaceId: namespaceID,
				},
			})
		}
	}

	if !hasChange {
		return nil, fmt.Errorf("no updates to be made")
	}
	existingEndpoint.Spec.PolicySpecs = updatedPolicySpecs
	return c.callUpdateEndpoint(existingEndpoint, resourceVersion, asyncOperationId)
}

func (c *NexusClient) setAllowedNamespaces(
	existingEndpoint *nexus.Endpoint,
	namespaceIDs []string,
	resourceVersion string,
	asyncOperationId string,
) (*operation.AsyncOperation, error) {
	updatedPolicySpecs := make([]*nexus.EndpointPolicySpec, len(namespaceIDs))
	for i, namespaceID := range namespaceIDs {
		updatedPolicySpecs[i] = &nexus.EndpointPolicySpec{
			AllowedCloudNamespacePolicySpec: &nexus.AllowedCloudNamespacePolicySpec{
				NamespaceId: namespaceID,
			},
		}
	}

	existingEndpoint.Spec.PolicySpecs = updatedPolicySpecs
	return c.callUpdateEndpoint(existingEndpoint, resourceVersion, asyncOperationId)
}

func (c *NexusClient) removeAllowedNamespaces(
	existingEndpoint *nexus.Endpoint,
	namespaceIDsToRemove []string,
	resourceVersion string,
	asyncOperationId string,
) (*operation.AsyncOperation, error) {
	existingPolicySpecs := existingEndpoint.Spec.PolicySpecs
	namespaceIDsToRemoveMap := make(map[string]struct{}, len(namespaceIDsToRemove))
	for _, namespaceID := range namespaceIDsToRemove {
		namespaceIDsToRemoveMap[namespaceID] = struct{}{}
	}

	var updatedPolicySpecs []*nexus.EndpointPolicySpec
	for _, existingPolicySpec := range existingPolicySpecs {
		if _, ok := namespaceIDsToRemoveMap[existingPolicySpec.AllowedCloudNamespacePolicySpec.NamespaceId]; !ok {
			updatedPolicySpecs = append(updatedPolicySpecs, existingPolicySpec)
		}
	}

	if len(updatedPolicySpecs) == len(existingPolicySpecs) {
		return nil, fmt.Errorf("no updates to be made")
	}
	existingEndpoint.Spec.PolicySpecs = updatedPolicySpecs
	return c.callUpdateEndpoint(existingEndpoint, resourceVersion, asyncOperationId)
}

func (c *NexusClient) deleteEndpoint(
	endpointID string,
	resourceVersion string,
	asyncOperationId string,
) (*operation.AsyncOperation, error) {
	resp, err := c.client.DeleteNexusEndpoint(c.ctx, &cloudservice.DeleteNexusEndpointRequest{
		EndpointId:       endpointID,
		ResourceVersion:  resourceVersion,
		AsyncOperationId: asyncOperationId,
	})
	if err != nil {
		return nil, err
	}
	return resp.AsyncOperation, nil
}

func NewNexusCommand(getNexusClientFn GetNexusClientFn) (CommandOut, error) {
	var c *NexusClient
	endpointNameFlag := &cli.StringFlag{
		Name:     "name",
		Aliases:  []string{"n"},
		Usage:    "Endpoint name",
		Required: true,
	}
	targetNamespaceFlag := &cli.StringFlag{
		Name:     "target-namespace",
		Aliases:  []string{"tns"},
		Usage:    "Namespace in which a handler worker will be polling for Nexus tasks on",
		Required: true,
	}
	targetNamespaceFlagOptional := &cli.StringFlag{
		Name:     targetNamespaceFlag.Name,
		Aliases:  targetNamespaceFlag.Aliases,
		Usage:    targetNamespaceFlag.Usage + " (optional)",
		Required: false,
	}
	targetTaskQueueFlag := &cli.StringFlag{
		Name:     "target-task-queue",
		Aliases:  []string{"ttq"},
		Usage:    "Task Queue in which a handler worker will be polling for Nexus tasks on",
		Required: true,
	}
	targetTaskQueueFlagOptional := &cli.StringFlag{
		Name:     targetTaskQueueFlag.Name,
		Aliases:  targetTaskQueueFlag.Aliases,
		Usage:    targetTaskQueueFlag.Usage + " (optional)",
		Required: false,
	}
	allowNamespaceFlag := &cli.StringSliceFlag{
		Name:     "allow-namespace",
		Aliases:  []string{"ans"},
		Usage:    "Namespace that is allowed to call this endpoint",
		Required: true,
	}
	namespaceFlag := &cli.StringSliceFlag{
		Name:     "namespace",
		Aliases:  []string{"ns"},
		Usage:    "Namespace that is allowed to call this endpoint",
		Required: true,
	}
	return CommandOut{
		Command: &cli.Command{
			Name:    "nexus",
			Aliases: []string{"nxs"},
			Usage:   "Commands for managing Nexus operations (EXPERIMENTAL)",
			Before: func(ctx *cli.Context) error {
				var err error
				c, err = getNexusClientFn(ctx)
				return err
			},
			Subcommands: []*cli.Command{
				{
					Name:        "endpoint",
					Aliases:     []string{"ep"},
					Usage:       "Commands for managing Nexus Endpoints (EXPERIMENTAL)",
					Description: "Endpoint commands enable managing Nexus Endpoints",
					Subcommands: []*cli.Command{
						{
							Name:        "get",
							Aliases:     []string{"g"},
							Usage:       "Get a Nexus Endpoint by name (EXPERIMENTAL)",
							Description: "This command gets a Nexus Endpoint configuration by name from the Cloud Account",
							Flags: []cli.Flag{
								endpointNameFlag,
							},
							Action: func(ctx *cli.Context) error {
								endpointName := ctx.String(endpointNameFlag.Name)
								endpoint, err := c.getEndpointByName(endpointName)
								if err != nil {
									return err
								}
								return PrintProto(endpoint)
							},
						},
						{
							Name:        "list",
							Aliases:     []string{"l"},
							Usage:       "List Nexus Endpoints (EXPERIMENTAL)",
							Description: "This command lists all Nexus Endpoint configurations on the Cloud Account",
							Flags:       []cli.Flag{},
							Action: func(ctx *cli.Context) error {
								endpoints, err := c.listEndpoints("")
								if err != nil {
									return err
								}
								return PrintObj(endpoints)
							},
						},
						{
							Name:    "create",
							Aliases: []string{"c"},
							Usage:   "Create a new Nexus Endpoint (EXPERIMENTAL)",
							Description: "This command creates a new Nexus Endpoint on the Cloud Account.\n" +
								"An endpoint name is used by in workflow code to invoke Nexus operations.\n" +
								"The endpoint target is a worker and `--target-namespace` and `--target-task-queue` must both be provided.\n" +
								"This will fail if an endpoint with the same name is already registered",
							Flags: []cli.Flag{
								endpointNameFlag,
								targetNamespaceFlag,
								targetTaskQueueFlag,
								allowNamespaceFlag,
								RequestIDFlag,
							},
							Action: func(ctx *cli.Context) error {
								resp, err := c.createEndpoint(
									ctx.String(endpointNameFlag.Name),
									ctx.String(targetNamespaceFlag.Name),
									ctx.String(targetTaskQueueFlag.Name),
									ctx.StringSlice(allowNamespaceFlag.Name),
									ctx.String(RequestIDFlag.Name),
								)
								if err != nil {
									return err
								}
								return PrintProto(resp)
							},
						},
						{
							Name:    "update",
							Aliases: []string{"u"},
							Usage:   "Update an existing Nexus Endpoint (EXPERIMENTAL)",
							Description: "This command updates an existing Nexus Endpoint on the Cloud Account.\n" +
								"An endpoint name is used by in workflow code to invoke Nexus operations.\n" +
								"The endpoint target is a worker and `--target-namespace` and `--target-task-queue` must both be provided.\n" +
								"Only the fields that are provided will be updated",
							Flags: []cli.Flag{
								endpointNameFlag,
								targetNamespaceFlagOptional,
								targetTaskQueueFlagOptional,
								ResourceVersionFlag,
								RequestIDFlag,
							},
							Action: func(ctx *cli.Context) error {
								endpointName := ctx.String(endpointNameFlag.Name)
								targetNamespaceID := ctx.String(targetNamespaceFlagOptional.Name)
								targetTaskQueue := ctx.String(targetTaskQueueFlagOptional.Name)
								resourceVersion := ctx.String(ResourceVersionFlag.Name)

								if targetNamespaceID == "" && targetTaskQueue == "" {
									return fmt.Errorf("no updates to be made")
								}
								existingEndpoint, err := c.getEndpointByName(endpointName)
								if err != nil {
									return err
								}
								if resourceVersion == "" {
									resourceVersion = existingEndpoint.ResourceVersion
								}

								if targetNamespaceID == existingEndpoint.Spec.TargetSpec.WorkerTargetSpec.NamespaceId && targetTaskQueue == existingEndpoint.Spec.TargetSpec.WorkerTargetSpec.TaskQueue {
									return fmt.Errorf("no updates to be made")
								}

								requestID := ctx.String(RequestIDFlag.Name)

								resp, err := c.patchEndpoint(existingEndpoint, targetNamespaceID, targetTaskQueue, resourceVersion, requestID)
								if err != nil {
									return err
								}
								return PrintProto(resp)
							},
						},
						{
							Name:    "allowed-namespace",
							Aliases: []string{"an"},
							Usage:   "Allowed namespace operations for a Nexus Endpoint (EXPERIMENTAL)",
							Subcommands: []*cli.Command{
								{
									Name:    "add",
									Aliases: []string{"a"},
									Usage:   "Add allowed namespaces to a Nexus Endpoint (EXPERIMENTAL)",
									Flags: []cli.Flag{
										endpointNameFlag,
										namespaceFlag,
										ResourceVersionFlag,
										RequestIDFlag,
									},
									Action: func(ctx *cli.Context) error {
										endpointName := ctx.String(endpointNameFlag.Name)
										resourceVersion := ctx.String(ResourceVersionFlag.Name)
										namespaces := ctx.StringSlice(namespaceFlag.Name)
										requestID := ctx.String(RequestIDFlag.Name)

										existingEndpoint, err := c.getEndpointByName(endpointName)
										if err != nil {
											return err
										}
										if resourceVersion == "" {
											resourceVersion = existingEndpoint.ResourceVersion
										}

										resp, err := c.addAllowedNamespaces(existingEndpoint, namespaces, resourceVersion, requestID)
										if err != nil {
											return err
										}
										return PrintProto(resp)
									},
								},
								{
									Name:    "list",
									Aliases: []string{"l"},
									Usage:   "List allowed namespaces of a Nexus Endpoint (EXPERIMENTAL)",
									Flags: []cli.Flag{
										endpointNameFlag,
									},
									Action: func(ctx *cli.Context) error {
										endpointName := ctx.String(endpointNameFlag.Name)

										existingEndpoint, err := c.getEndpointByName(endpointName)
										if err != nil {
											return err
										}

										existingPolicySpecs := existingEndpoint.Spec.PolicySpecs
										existingAllowedNamespaceIDs := make([]string, len(existingPolicySpecs))
										for i, policySpec := range existingPolicySpecs {
											existingAllowedNamespaceIDs[i] = policySpec.AllowedCloudNamespacePolicySpec.NamespaceId
										}
										return PrintObj(existingAllowedNamespaceIDs)
									},
								},
								{
									Name:    "set",
									Aliases: []string{"s"},
									Usage:   "Set allowed namespaces of a Nexus Endpoint (EXPERIMENTAL)",
									Flags: []cli.Flag{
										endpointNameFlag,
										namespaceFlag,
										ResourceVersionFlag,
										RequestIDFlag,
									},
									Action: func(ctx *cli.Context) error {
										endpointName := ctx.String(endpointNameFlag.Name)
										namespaces := ctx.StringSlice(namespaceFlag.Name)
										requestID := ctx.String(RequestIDFlag.Name)

										existingEndpoint, err := c.getEndpointByName(endpointName)
										if err != nil {
											return err
										}
										resourceVersion := ctx.String(ResourceVersionFlag.Name)
										if resourceVersion == "" {
											resourceVersion = existingEndpoint.ResourceVersion
										}

										resp, err := c.setAllowedNamespaces(existingEndpoint, namespaces, resourceVersion, requestID)
										if err != nil {
											return err
										}
										return PrintProto(resp)
									},
								},
								{
									Name:    "remove",
									Aliases: []string{"r"},
									Usage:   "Remove allowed namespaces from a Nexus Endpoint (EXPERIMENTAL)",
									Flags: []cli.Flag{
										endpointNameFlag,
										namespaceFlag,
										ResourceVersionFlag,
										RequestIDFlag,
									},
									Action: func(ctx *cli.Context) error {
										endpointName := ctx.String(endpointNameFlag.Name)
										namespaces := ctx.StringSlice(namespaceFlag.Name)
										requestID := ctx.String(RequestIDFlag.Name)

										existingEndpoint, err := c.getEndpointByName(endpointName)
										if err != nil {
											return err
										}
										resourceVersion := ctx.String(ResourceVersionFlag.Name)
										if resourceVersion == "" {
											resourceVersion = existingEndpoint.ResourceVersion
										}

										resp, err := c.removeAllowedNamespaces(existingEndpoint, namespaces, resourceVersion, requestID)
										if err != nil {
											return err
										}
										return PrintProto(resp)
									},
								},
							},
						},
						{
							Name:        "delete",
							Aliases:     []string{"d"},
							Usage:       "Delete a Nexus Endpoint (EXPERIMENTAL)",
							Description: "This command deletes a Nexus Endpoint on the Cloud Account.\n",
							Flags: []cli.Flag{
								endpointNameFlag,
								ResourceVersionFlag,
								RequestIDFlag,
							},
							Action: func(ctx *cli.Context) error {
								endpointName := ctx.String(endpointNameFlag.Name)
								resourceVersion := ctx.String(ResourceVersionFlag.Name)
								requestID := ctx.String(RequestIDFlag.Name)

								existingEndpoint, err := c.getEndpointByName(endpointName)
								if err != nil {
									return err
								}
								if resourceVersion == "" {
									resourceVersion = existingEndpoint.ResourceVersion
								}

								resp, err := c.deleteEndpoint(existingEndpoint.Id, resourceVersion, requestID)
								if err != nil {
									return err
								}
								return PrintProto(resp)
							},
						},
					},
				},
			},
		},
	}, nil
}
