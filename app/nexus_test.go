package app

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/nexus/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/operation/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/resource/v1"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	cloudservicemock "github.com/temporalio/tcld/protogen/apimock/cloudservice/v1"
	"github.com/urfave/cli/v2"
)

func TestNexus(t *testing.T) {
	suite.Run(t, new(NexusTestSuite))
}

type NexusTestSuite struct {
	suite.Suite
	cliApp           *cli.App
	mockCtrl         *gomock.Controller
	mockCloudService *cloudservicemock.MockCloudServiceClient
}

func (s *NexusTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockCloudService = cloudservicemock.NewMockCloudServiceClient(s.mockCtrl)
	out, err := NewNexusCommand(func(ctx *cli.Context) (*NexusClient, error) {
		return &NexusClient{
			ctx:    context.TODO(),
			client: s.mockCloudService,
		}, nil
	})
	s.Require().NoError(err)
	AutoConfirmFlag.Value = true
	s.cliApp = &cli.App{
		Name:     "test",
		Commands: []*cli.Command{out.Command},
		Flags: []cli.Flag{
			AutoConfirmFlag,
		},
	}
}

func (s *NexusTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *NexusTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

const exampleDescriptionStr = "test description"

func getExampleNexusEndpoint() *nexus.Endpoint {
	return &nexus.Endpoint{
		Id:              "test-endpoint-id",
		ResourceVersion: "test-resource-version",
		Spec: &nexus.EndpointSpec{
			TargetSpec: &nexus.EndpointTargetSpec{
				Variant: &nexus.EndpointTargetSpec_WorkerTargetSpec{
					WorkerTargetSpec: &nexus.WorkerTargetSpec{
						NamespaceId: "test-namespace-name.test-account-id",
						TaskQueue:   "test-task-queue",
					},
				},
			},
			Name:        "test_name",
			Description: newAPIPayloadFromString(exampleDescriptionStr),
			PolicySpecs: []*nexus.EndpointPolicySpec{
				{
					Variant: &nexus.EndpointPolicySpec_AllowedCloudNamespacePolicySpec{
						AllowedCloudNamespacePolicySpec: &nexus.AllowedCloudNamespacePolicySpec{
							NamespaceId: "test-caller-namespace.test-account-id",
						},
					},
				},
				{
					Variant: &nexus.EndpointPolicySpec_AllowedCloudNamespacePolicySpec{
						AllowedCloudNamespacePolicySpec: &nexus.AllowedCloudNamespacePolicySpec{
							NamespaceId: "test-caller-namespace-2.test-account-id",
						},
					},
				},
			},
		},
		State:            resource.RESOURCE_STATE_ACTIVATING,
		AsyncOperationId: "test-request-id",
		CreatedTime:      &types.Timestamp{Seconds: time.Date(time.Now().Year(), time.April, 12, 0, 0, 0, 0, time.UTC).Unix()},
		LastModifiedTime: &types.Timestamp{Seconds: time.Date(time.Now().Year(), time.April, 14, 0, 0, 0, 0, time.UTC).Unix()},
	}
}

func (s *NexusTestSuite) TestEndpointGet() {
	s.Error(s.RunCmd("nexus", "endpoint", "get"))

	s.Error(s.RunCmd("nexus", "endpoint", "get", "--name"))

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found")).Times(1)
	s.Error(s.RunCmd("nexus", "endpoint", "get", "--name", "test_nexus_endpoint_name"))

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "get", "--name", "test_nexus_endpoint_name"))
}

func (s *NexusTestSuite) TestEndpointList() {
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(nil, errors.New("list error")).Times(1)
	s.Error(s.RunCmd("nexus", "endpoint", "list"))

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{}}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "list"))

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "list"))
}

func (s *NexusTestSuite) TestEndpointCreate() {
	exampleEndpoint := getExampleNexusEndpoint()

	s.mockCloudService.EXPECT().CreateNexusEndpoint(gomock.Any(), gomock.Any()).Return(nil, errors.New("create error")).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "create",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr,
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[1].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "create error")

	// test success all fields - description file
	path := "nexus_endpoint_description_test.md"
	s.NoError(os.WriteFile(path, []byte("*my awesome endpoint*\n"), 0644))
	defer os.Remove(path)
	s.mockCloudService.EXPECT().CreateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateNexusEndpointResponse{
		EndpointId: exampleEndpoint.Id,
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "create",
		"--name", exampleEndpoint.Spec.Name,
		"--description-file", path,
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[1].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// test success all fields - description string
	s.mockCloudService.EXPECT().CreateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateNexusEndpointResponse{
		EndpointId: exampleEndpoint.Id,
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "create",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr,
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[1].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// test success mandatory fields
	s.mockCloudService.EXPECT().CreateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.CreateNexusEndpointResponse{
		EndpointId: exampleEndpoint.Id,
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "create",
		"--name", exampleEndpoint.Spec.Name,
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[1].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// provided both --description and --description-file
	s.EqualError(s.RunCmd("nexus", "endpoint", "create",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr,
		"--description-file", "nexus_endpoint_description_test.md",
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[1].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "provided both --description and --description-file")

	// empty description file
	path2 := "nexus_endpoint_empty_description_test.md"
	s.NoError(os.WriteFile(path2, []byte(""), 0644))
	defer os.Remove(path2)
	s.EqualError(s.RunCmd("nexus", "endpoint", "create",
		"--name", exampleEndpoint.Spec.Name,
		"--description-file", path2,
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--allow-namespace", exampleEndpoint.Spec.PolicySpecs[1].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "empty description file: \"nexus_endpoint_empty_description_test.md\"")
}

func (s *NexusTestSuite) TestEndpointUpdate() {
	exampleEndpoint := getExampleNexusEndpoint()

	// endpoint not found
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue+"-updated",
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "endpoint not found")

	// update error
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(nil, errors.New("update error")).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue+"-updated",
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "update error")

	// update target-task-queue success
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue+"-updated",
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// update target-namespace success
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId+"-updated",
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// update description file success
	path := "nexus_endpoint_description_test.md"
	s.NoError(os.WriteFile(path, []byte("*my awesome endpoint*\n"), 0644))
	defer os.Remove(path)
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--description-file", path,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// update description success
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr+"-updated",
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// unset-description success
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "update",
		"--unset-description",
		"--name", exampleEndpoint.Spec.Name,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// update all success
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr+"-updated",
		"--target-namespace", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().NamespaceId+"-updated",
		"--target-task-queue", exampleEndpoint.Spec.TargetSpec.GetWorkerTargetSpec().TaskQueue+"-updated",
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	// no updates to be made
	s.EqualError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "no updates to be made")

	// no updates to be made
	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "no updates to be made")

	// provided both --description and --description-file
	s.EqualError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr+"-updated",
		"--description-file", "nexus_endpoint_description_test.md",
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "provided both --description and --description-file")

	// --unset-description should not be set if --description or --description-file is set
	s.EqualError(s.RunCmd("nexus", "endpoint", "update",
		"--name", exampleEndpoint.Spec.Name,
		"--description", exampleDescriptionStr+"-updated",
		"--unset-description",
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "--unset-description should not be set if --description or --description-file is set")

}

func (s *NexusTestSuite) TestEndpointAllowedNamespaceAdd() {
	exampleEndpoint := getExampleNexusEndpoint()

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "add",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", "test-another-caller-namespace.test-account-id",
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "endpoint not found")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(nil, errors.New("update error")).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "add",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", "test-another-caller-namespace.test-account-id",
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "update error")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "add",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", "test-another-caller-namespace.test-account-id",
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "add",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "no updates to be made")
}

func (s *NexusTestSuite) TestEndpointAllowedNamespaceSet() {
	exampleEndpoint := getExampleNexusEndpoint()

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "set",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "endpoint not found")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(nil, errors.New("update error")).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "set",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "update error")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "set",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))
}

func (s *NexusTestSuite) TestEndpointAllowedNamespaceList() {
	exampleEndpoint := getExampleNexusEndpoint()

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "list", "--name", exampleEndpoint.Spec.Name), "endpoint not found")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{}, errors.New("list error")).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "list", "--name", exampleEndpoint.Spec.Name), "list error")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "list", "--name", exampleEndpoint.Spec.Name))
}

func (s *NexusTestSuite) TestEndpointAllowedNamespaceRemove() {
	exampleEndpoint := getExampleNexusEndpoint()

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "remove",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "endpoint not found")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(nil, errors.New("update error")).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "remove",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "update error")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().UpdateNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.UpdateNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "remove",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", exampleEndpoint.Spec.PolicySpecs[0].GetAllowedCloudNamespacePolicySpec().NamespaceId,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "allowed-namespace", "remove",
		"--name", exampleEndpoint.Spec.Name,
		"--namespace", "test-another-caller-namespace.test-account-id",
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "no updates to be made")
}

func (s *NexusTestSuite) TestEndpointDelete() {
	exampleEndpoint := getExampleNexusEndpoint()

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{}}, nil).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "delete",
		"--name", exampleEndpoint.Spec.Name,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "endpoint not found")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().DeleteNexusEndpoint(gomock.Any(), gomock.Any()).Return(nil, errors.New("delete error")).Times(1)
	s.EqualError(s.RunCmd("nexus", "endpoint", "delete",
		"--name", exampleEndpoint.Spec.Name,
		"--request-id", exampleEndpoint.AsyncOperationId,
	), "delete error")

	s.mockCloudService.EXPECT().GetNexusEndpoints(gomock.Any(), gomock.Any()).Return(&cloudservice.GetNexusEndpointsResponse{Endpoints: []*nexus.Endpoint{getExampleNexusEndpoint()}}, nil).Times(1)
	s.mockCloudService.EXPECT().DeleteNexusEndpoint(gomock.Any(), gomock.Any()).Return(&cloudservice.DeleteNexusEndpointResponse{
		AsyncOperation: &operation.AsyncOperation{
			Id: exampleEndpoint.AsyncOperationId,
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("nexus", "endpoint", "delete",
		"--name", exampleEndpoint.Spec.Name,
		"--request-id", exampleEndpoint.AsyncOperationId,
	))
}
