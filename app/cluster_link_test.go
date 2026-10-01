package app

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/clusterlink/v1"
	cloudservicemock "github.com/temporalio/tcld/protogen/apimock/cloudservice/v1"
	"github.com/urfave/cli/v2"
)

func TestParseClusterLinkConnectionStates(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		values   []string
		expected []clusterlink.ClusterLink_ConnectionState
		err      string
	}{
		{
			name:     "empty",
			values:   nil,
			expected: nil,
		},
		{
			name: "all states",
			values: []string{
				"disconnected",
				"connecting",
				"connected",
				"connect-failed",
				"disconnecting",
				"disconnect-failed",
			},
			expected: []clusterlink.ClusterLink_ConnectionState{
				clusterlink.CONNECTION_STATE_DISCONNECTED,
				clusterlink.CONNECTION_STATE_CONNECTING,
				clusterlink.CONNECTION_STATE_CONNECTED,
				clusterlink.CONNECTION_STATE_CONNECT_FAILED,
				clusterlink.CONNECTION_STATE_DISCONNECTING,
				clusterlink.CONNECTION_STATE_DISCONNECT_FAILED,
			},
		},
		{
			name: "case insensitive",
			values: []string{
				"Connect_Failed",
			},
			expected: []clusterlink.ClusterLink_ConnectionState{
				clusterlink.CONNECTION_STATE_CONNECT_FAILED,
			},
		},
		{
			name: "unspecified",
			values: []string{
				"unspecified",
			},
			err: `invalid Cluster Link connection state "unspecified"`,
		},
		{
			name: "unknown",
			values: []string{
				"not-a-state",
			},
			err: `invalid Cluster Link connection state "not-a-state"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actual, err := parseClusterLinkConnectionStates(testCase.values)
			if testCase.err != "" {
				require.EqualError(t, err, testCase.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expected, actual)
		})
	}
}

func TestClusterLinkCreateCommand(t *testing.T) {
	acceptedClientCA := []byte("accepted-client-ca")
	acceptedClientCAPath := writeClusterLinkTestFile(t, "accepted-client-ca.pem", acceptedClientCA)

	testCases := []struct {
		name            string
		arguments       []string
		expectedRequest *cloudservice.CreateClusterLinkRequest
		response        *cloudservice.CreateClusterLinkResponse
		serviceError    error
		errorContains   string
	}{
		{
			name: "missing display name",
			arguments: []string{
				"cluster-link",
				"create",
				"--region", "aws-us-west-2",
				"--accepted-client-ca-file", acceptedClientCAPath,
			},
			errorContains: `Required flag "display-name" not set`,
		},
		{
			name: "missing region",
			arguments: []string{
				"cluster-link",
				"create",
				"--display-name", "production",
				"--accepted-client-ca-file", acceptedClientCAPath,
			},
			errorContains: `Required flag "region" not set`,
		},
		{
			name: "missing certificate",
			arguments: []string{
				"cluster-link",
				"create",
				"--display-name", "production",
				"--region", "aws-us-west-2",
			},
			errorContains: `Required flag "accepted-client-ca-file" not set`,
		},
		{
			name: "service error",
			arguments: []string{
				"cluster-link",
				"create",
				"--display-name", "production",
				"--region", "aws-us-west-2",
				"--accepted-client-ca-file", acceptedClientCAPath,
				"--request-id", "request-id",
			},
			expectedRequest: &cloudservice.CreateClusterLinkRequest{
				Spec: &clusterlink.ClusterLinkSpec{
					DesiredConnectionState: clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
					DisplayName:            "production",
					Region:                 "aws-us-west-2",
					Endpoint: &clusterlink.ClusterLinkEndpointSpec{
						Type: clusterlink.ENDPOINT_TYPE_PUBLIC_DNS,
						Security: &clusterlink.ClusterLinkEndpointSecuritySpec{
							AcceptedClientCa: acceptedClientCA,
						},
					},
				},
				AsyncOperationId: "request-id",
			},
			serviceError:  errors.New("create failed"),
			errorContains: "create failed",
		},
		{
			name: "success without external cluster address",
			arguments: []string{
				"cluster-link",
				"create",
				"--display-name", "production",
				"--region", "aws-us-west-2",
				"--accepted-client-ca-file", acceptedClientCAPath,
				"--request-id", "request-id",
			},
			expectedRequest: &cloudservice.CreateClusterLinkRequest{
				Spec: &clusterlink.ClusterLinkSpec{
					DesiredConnectionState: clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
					DisplayName:            "production",
					Region:                 "aws-us-west-2",
					Endpoint: &clusterlink.ClusterLinkEndpointSpec{
						Type: clusterlink.ENDPOINT_TYPE_PUBLIC_DNS,
						Security: &clusterlink.ClusterLinkEndpointSecuritySpec{
							AcceptedClientCa: acceptedClientCA,
						},
					},
				},
				AsyncOperationId: "request-id",
			},
			response: &cloudservice.CreateClusterLinkResponse{
				ClusterLinkId: "cluster-link-id",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockController := gomock.NewController(t)
			mockService := cloudservicemock.NewMockCloudServiceClient(mockController)
			application := newClusterLinkTestApp(t, mockService)

			if testCase.expectedRequest != nil {
				mockService.EXPECT().
					CreateClusterLink(gomock.Any(), testCase.expectedRequest).
					Return(testCase.response, testCase.serviceError)
			}

			err := application.Run(append([]string{"tcld"}, testCase.arguments...))
			if testCase.errorContains != "" {
				require.ErrorContains(t, err, testCase.errorContains)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestClusterLinkReadCommands(t *testing.T) {
	testCases := []struct {
		name                string
		arguments           []string
		expectedGetRequest  *cloudservice.GetClusterLinkRequest
		getResponse         *cloudservice.GetClusterLinkResponse
		expectedListRequest *cloudservice.GetClusterLinksRequest
		listResponse        *cloudservice.GetClusterLinksResponse
		serviceError        error
		errorContains       string
	}{
		{
			name: "get requires id",
			arguments: []string{
				"cluster-link",
				"get",
			},
			errorContains: `Required flag "cluster-link-id" not set`,
		},
		{
			name: "get service error",
			arguments: []string{
				"cluster-link",
				"get",
				"--cluster-link-id", "cluster-link-id",
			},
			expectedGetRequest: &cloudservice.GetClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
			},
			serviceError:  errors.New("get failed"),
			errorContains: "get failed",
		},
		{
			name: "get success",
			arguments: []string{
				"cluster-link",
				"get",
				"--cluster-link-id", "cluster-link-id",
			},
			expectedGetRequest: &cloudservice.GetClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
			},
			getResponse: &cloudservice.GetClusterLinkResponse{
				ClusterLink: &clusterlink.ClusterLink{
					Id: "cluster-link-id",
				},
			},
		},
		{
			name: "list rejects invalid state",
			arguments: []string{
				"cluster-link",
				"list",
				"--connection-state", "invalid",
			},
			errorContains: `invalid Cluster Link connection state "invalid"`,
		},
		{
			name: "list service error",
			arguments: []string{
				"cluster-link",
				"list",
				"--region", "aws-us-west-2",
				"--connection-state", "connected",
				"--connection-state", "disconnect-failed",
				"--page-size", "25",
				"--page-token", "next-page",
			},
			expectedListRequest: &cloudservice.GetClusterLinksRequest{
				PageSize:  25,
				PageToken: "next-page",
				Region:    "aws-us-west-2",
				ConnectionStates: []clusterlink.ClusterLink_ConnectionState{
					clusterlink.CONNECTION_STATE_CONNECTED,
					clusterlink.CONNECTION_STATE_DISCONNECT_FAILED,
				},
			},
			serviceError:  errors.New("list failed"),
			errorContains: "list failed",
		},
		{
			name: "list success",
			arguments: []string{
				"cluster-link",
				"list",
			},
			expectedListRequest: &cloudservice.GetClusterLinksRequest{},
			listResponse: &cloudservice.GetClusterLinksResponse{
				ClusterLinks: []*clusterlink.ClusterLink{
					{
						Id: "cluster-link-id",
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockController := gomock.NewController(t)
			mockService := cloudservicemock.NewMockCloudServiceClient(mockController)
			application := newClusterLinkTestApp(t, mockService)

			if testCase.expectedGetRequest != nil {
				mockService.EXPECT().
					GetClusterLink(gomock.Any(), testCase.expectedGetRequest).
					Return(testCase.getResponse, testCase.serviceError)
			}
			if testCase.expectedListRequest != nil {
				mockService.EXPECT().
					GetClusterLinks(gomock.Any(), testCase.expectedListRequest).
					Return(testCase.listResponse, testCase.serviceError)
			}

			err := application.Run(append([]string{"tcld"}, testCase.arguments...))
			if testCase.errorContains != "" {
				require.ErrorContains(t, err, testCase.errorContains)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestClusterLinkMutationCommands(t *testing.T) {
	acceptedClientCA := []byte("accepted-client-ca")
	replacementClientCA := []byte("replacement-client-ca")
	replacementClientCAPath := writeClusterLinkTestFile(t, "replacement-client-ca.pem", replacementClientCA)

	testCases := []struct {
		name                  string
		arguments             []string
		stored                *clusterlink.ClusterLink
		getError              error
		expectedUpdateRequest *cloudservice.UpdateClusterLinkRequest
		updateError           error
		errorContains         string
	}{
		{
			name: "update requires a mutable field",
			arguments: []string{
				"cluster-link",
				"update",
				"--cluster-link-id", "cluster-link-id",
			},
			errorContains: "--display-name or --accepted-client-ca-file is required",
		},
		{
			name: "get failure",
			arguments: []string{
				"cluster-link",
				"connect",
				"--cluster-link-id", "cluster-link-id",
			},
			getError:      errors.New("get failed"),
			errorContains: "get failed",
		},
		{
			name: "stored specification is missing",
			arguments: []string{
				"cluster-link",
				"connect",
				"--cluster-link-id", "cluster-link-id",
			},
			stored: &clusterlink.ClusterLink{
				Id:              "cluster-link-id",
				ResourceVersion: "resource-version",
			},
			errorContains: `cluster link "cluster-link-id" has no specification`,
		},
		{
			name: "display name update preserves complete specification",
			arguments: []string{
				"cluster-link",
				"update",
				"--cluster-link-id", "cluster-link-id",
				"--display-name", "new display name",
				"--request-id", "request-id",
			},
			stored: clusterLinkTestResource(
				clusterlink.DESIRED_CONNECTION_STATE_CONNECTED,
				clusterlink.CONNECTION_STATE_CONNECTED,
				acceptedClientCA,
			),
			expectedUpdateRequest: &cloudservice.UpdateClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
				Spec: clusterLinkTestSpec(
					clusterlink.DESIRED_CONNECTION_STATE_CONNECTED,
					"new display name",
					acceptedClientCA,
				),
				ResourceVersion:  "resource-version",
				AsyncOperationId: "request-id",
			},
		},
		{
			name: "certificate update preserves complete specification",
			arguments: []string{
				"cluster-link",
				"update",
				"--cluster-link-id", "cluster-link-id",
				"--accepted-client-ca-file", replacementClientCAPath,
				"--resource-version", "override-version",
				"--request-id", "request-id",
			},
			stored: clusterLinkTestResource(
				clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
				clusterlink.CONNECTION_STATE_DISCONNECTED,
				acceptedClientCA,
			),
			expectedUpdateRequest: &cloudservice.UpdateClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
				Spec: clusterLinkTestSpec(
					clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
					"display name",
					replacementClientCA,
				),
				ResourceVersion:  "override-version",
				AsyncOperationId: "request-id",
			},
		},
		{
			name: "certificate update rejects a missing endpoint",
			arguments: []string{
				"cluster-link",
				"update",
				"--cluster-link-id", "cluster-link-id",
				"--accepted-client-ca-file", replacementClientCAPath,
			},
			stored: &clusterlink.ClusterLink{
				Id: "cluster-link-id",
				Spec: &clusterlink.ClusterLinkSpec{
					DisplayName: "display name",
				},
				ResourceVersion: "resource-version",
			},
			errorContains: "cluster link specification has no endpoint",
		},
		{
			name: "certificate update initializes endpoint security",
			arguments: []string{
				"cluster-link",
				"update",
				"--cluster-link-id", "cluster-link-id",
				"--accepted-client-ca-file", replacementClientCAPath,
			},
			stored: &clusterlink.ClusterLink{
				Id: "cluster-link-id",
				Spec: &clusterlink.ClusterLinkSpec{
					DesiredConnectionState: clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
					DisplayName:            "display name",
					Region:                 "aws-us-west-2",
					Endpoint: &clusterlink.ClusterLinkEndpointSpec{
						Type: clusterlink.ENDPOINT_TYPE_PUBLIC_DNS,
					},
				},
				ResourceVersion: "resource-version",
			},
			expectedUpdateRequest: &cloudservice.UpdateClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
				Spec: clusterLinkTestSpec(
					clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
					"display name",
					replacementClientCA,
				),
				ResourceVersion: "resource-version",
			},
		},
		{
			name: "connect changes only desired state",
			arguments: []string{
				"cluster-link",
				"connect",
				"--cluster-link-id", "cluster-link-id",
			},
			stored: clusterLinkTestResource(
				clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
				clusterlink.CONNECTION_STATE_DISCONNECTED,
				acceptedClientCA,
			),
			expectedUpdateRequest: &cloudservice.UpdateClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
				Spec: clusterLinkTestSpec(
					clusterlink.DESIRED_CONNECTION_STATE_CONNECTED,
					"display name",
					acceptedClientCA,
				),
				ResourceVersion: "resource-version",
			},
		},
		{
			name: "disconnect changes only desired state",
			arguments: []string{
				"cluster-link",
				"disconnect",
				"--cluster-link-id", "cluster-link-id",
			},
			stored: clusterLinkTestResource(
				clusterlink.DESIRED_CONNECTION_STATE_CONNECTED,
				clusterlink.CONNECTION_STATE_CONNECTED,
				acceptedClientCA,
			),
			expectedUpdateRequest: &cloudservice.UpdateClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
				Spec: clusterLinkTestSpec(
					clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
					"display name",
					acceptedClientCA,
				),
				ResourceVersion: "resource-version",
			},
		},
		{
			name: "update service error",
			arguments: []string{
				"cluster-link",
				"connect",
				"--cluster-link-id", "cluster-link-id",
			},
			stored: clusterLinkTestResource(
				clusterlink.DESIRED_CONNECTION_STATE_DISCONNECTED,
				clusterlink.CONNECTION_STATE_DISCONNECTED,
				acceptedClientCA,
			),
			expectedUpdateRequest: &cloudservice.UpdateClusterLinkRequest{
				ClusterLinkId: "cluster-link-id",
				Spec: clusterLinkTestSpec(
					clusterlink.DESIRED_CONNECTION_STATE_CONNECTED,
					"display name",
					acceptedClientCA,
				),
				ResourceVersion: "resource-version",
			},
			updateError:   errors.New("update failed"),
			errorContains: "update failed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockController := gomock.NewController(t)
			mockService := cloudservicemock.NewMockCloudServiceClient(mockController)
			application := newClusterLinkTestApp(t, mockService)

			if testCase.stored != nil || testCase.getError != nil {
				getCall := mockService.EXPECT().
					GetClusterLink(gomock.Any(), &cloudservice.GetClusterLinkRequest{
						ClusterLinkId: "cluster-link-id",
					}).
					Return(&cloudservice.GetClusterLinkResponse{
						ClusterLink: testCase.stored,
					}, testCase.getError)
				if testCase.expectedUpdateRequest != nil {
					gomock.InOrder(
						getCall,
						mockService.EXPECT().
							UpdateClusterLink(gomock.Any(), testCase.expectedUpdateRequest).
							Return(&cloudservice.UpdateClusterLinkResponse{}, testCase.updateError),
					)
				}
			}

			err := application.Run(append([]string{"tcld"}, testCase.arguments...))
			if testCase.errorContains != "" {
				require.ErrorContains(t, err, testCase.errorContains)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestClusterLinkDeleteCommand(t *testing.T) {
	testCases := []struct {
		name                  string
		arguments             []string
		stored                *clusterlink.ClusterLink
		getError              error
		expectedDeleteRequest *cloudservice.DeleteClusterLinkRequest
		deleteError           error
		errorContains         string
	}{
		{
			name: "missing id",
			arguments: []string{
				"cluster-link",
				"delete",
			},
			errorContains: `Required flag "cluster-link-id" not set`,
		},
		{
			name: "fetches resource version",
			arguments: []string{
				"cluster-link",
				"delete",
				"--cluster-link-id", "cluster-link-id",
				"--request-id", "request-id",
			},
			stored: &clusterlink.ClusterLink{
				Id:              "cluster-link-id",
				ResourceVersion: "resource-version",
			},
			expectedDeleteRequest: &cloudservice.DeleteClusterLinkRequest{
				ClusterLinkId:    "cluster-link-id",
				ResourceVersion:  "resource-version",
				AsyncOperationId: "request-id",
			},
		},
		{
			name: "uses explicit resource version without fetching",
			arguments: []string{
				"cluster-link",
				"delete",
				"--cluster-link-id", "cluster-link-id",
				"--resource-version", "override-version",
				"--request-id", "request-id",
			},
			expectedDeleteRequest: &cloudservice.DeleteClusterLinkRequest{
				ClusterLinkId:    "cluster-link-id",
				ResourceVersion:  "override-version",
				AsyncOperationId: "request-id",
			},
		},
		{
			name: "get failure",
			arguments: []string{
				"cluster-link",
				"delete",
				"--cluster-link-id", "cluster-link-id",
			},
			getError:      errors.New("get failed"),
			errorContains: "get failed",
		},
		{
			name: "delete failure",
			arguments: []string{
				"cluster-link",
				"delete",
				"--cluster-link-id", "cluster-link-id",
				"--resource-version", "resource-version",
			},
			expectedDeleteRequest: &cloudservice.DeleteClusterLinkRequest{
				ClusterLinkId:   "cluster-link-id",
				ResourceVersion: "resource-version",
			},
			deleteError:   errors.New("delete failed"),
			errorContains: "delete failed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockController := gomock.NewController(t)
			mockService := cloudservicemock.NewMockCloudServiceClient(mockController)
			application := newClusterLinkTestApp(t, mockService)

			var getCall *gomock.Call
			if testCase.stored != nil || testCase.getError != nil {
				getCall = mockService.EXPECT().
					GetClusterLink(gomock.Any(), &cloudservice.GetClusterLinkRequest{
						ClusterLinkId: "cluster-link-id",
					}).
					Return(&cloudservice.GetClusterLinkResponse{
						ClusterLink: testCase.stored,
					}, testCase.getError)
			}
			if testCase.expectedDeleteRequest != nil {
				deleteCall := mockService.EXPECT().
					DeleteClusterLink(gomock.Any(), testCase.expectedDeleteRequest).
					Return(&cloudservice.DeleteClusterLinkResponse{}, testCase.deleteError)
				if getCall != nil {
					gomock.InOrder(getCall, deleteCall)
				}
			}

			err := application.Run(append([]string{"tcld"}, testCase.arguments...))
			if testCase.errorContains != "" {
				require.ErrorContains(t, err, testCase.errorContains)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestClusterLinkCommandSurface(t *testing.T) {
	t.Parallel()

	commandOutput, err := NewClusterLinkCommand(func(*cli.Context) (*ClusterLinkClient, error) {
		return nil, errors.New("not called")
	})
	require.NoError(t, err)

	expectedSubcommands := []string{
		"create",
		"get",
		"list",
		"update",
		"connect",
		"disconnect",
		"delete",
	}
	actualSubcommands := make([]string, 0, len(commandOutput.Command.Subcommands))
	for _, subcommand := range commandOutput.Command.Subcommands {
		actualSubcommands = append(actualSubcommands, subcommand.Name)
	}
	require.ElementsMatch(t, expectedSubcommands, actualSubcommands)

	testCases := []struct {
		name              string
		subcommand        string
		expectedFlagNames []string
	}{
		{
			name:       "create",
			subcommand: "create",
			expectedFlagNames: []string{
				"display-name",
				"region",
				"accepted-client-ca-file",
				"request-id",
			},
		},
		{
			name:       "get",
			subcommand: "get",
			expectedFlagNames: []string{
				"cluster-link-id",
			},
		},
		{
			name:       "list",
			subcommand: "list",
			expectedFlagNames: []string{
				"region",
				"connection-state",
				"page-size",
				"page-token",
			},
		},
		{
			name:       "update",
			subcommand: "update",
			expectedFlagNames: []string{
				"cluster-link-id",
				"display-name",
				"accepted-client-ca-file",
				"resource-version",
				"request-id",
			},
		},
		{
			name:       "connect",
			subcommand: "connect",
			expectedFlagNames: []string{
				"cluster-link-id",
				"resource-version",
				"request-id",
			},
		},
		{
			name:       "disconnect",
			subcommand: "disconnect",
			expectedFlagNames: []string{
				"cluster-link-id",
				"resource-version",
				"request-id",
			},
		},
		{
			name:       "delete",
			subcommand: "delete",
			expectedFlagNames: []string{
				"cluster-link-id",
				"resource-version",
				"request-id",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			subcommand := findClusterLinkSubcommand(t, commandOutput.Command, testCase.subcommand)
			actualFlagNames := make([]string, 0, len(subcommand.Flags))
			for _, flag := range subcommand.Flags {
				actualFlagNames = append(actualFlagNames, flag.Names()[0])
			}

			require.ElementsMatch(t, testCase.expectedFlagNames, actualFlagNames)
			require.NotContains(t, actualFlagNames, "external-cluster-address")
		})
	}
}

func newClusterLinkTestApp(
	t *testing.T,
	mockService *cloudservicemock.MockCloudServiceClient,
) *cli.App {
	t.Helper()

	commandOutput, err := NewClusterLinkCommand(func(*cli.Context) (*ClusterLinkClient, error) {
		return &ClusterLinkClient{
			client: mockService,
			ctx:    context.Background(),
		}, nil
	})
	require.NoError(t, err)

	application, _ := NewTestApp(t, []*cli.Command{commandOutput.Command}, []cli.Flag{
		AutoConfirmFlag,
	})
	return application
}

func clusterLinkTestResource(
	desiredState clusterlink.ClusterLinkSpec_DesiredConnectionState,
	connectionState clusterlink.ClusterLink_ConnectionState,
	acceptedClientCA []byte,
) *clusterlink.ClusterLink {
	return &clusterlink.ClusterLink{
		Id: "cluster-link-id",
		Spec: clusterLinkTestSpec(
			desiredState,
			"display name",
			acceptedClientCA,
		),
		ResourceVersion: "resource-version",
		ConnectionState: connectionState,
		FailureMessage:  "customer-safe failure message",
		Endpoint: &clusterlink.ClusterLinkEndpoint{
			Endpoint: &clusterlink.ClusterLinkEndpoint_PublicDns{
				PublicDns: &clusterlink.PublicDNSEndpointDetails{
					Address: "cluster-link.example:8233",
				},
			},
		},
	}
}

func clusterLinkTestSpec(
	desiredState clusterlink.ClusterLinkSpec_DesiredConnectionState,
	displayName string,
	acceptedClientCA []byte,
) *clusterlink.ClusterLinkSpec {
	return &clusterlink.ClusterLinkSpec{
		DesiredConnectionState: desiredState,
		DisplayName:            displayName,
		Region:                 "aws-us-west-2",
		Endpoint: &clusterlink.ClusterLinkEndpointSpec{
			Type: clusterlink.ENDPOINT_TYPE_PUBLIC_DNS,
			Security: &clusterlink.ClusterLinkEndpointSecuritySpec{
				AcceptedClientCa: acceptedClientCA,
			},
		},
	}
}

func writeClusterLinkTestFile(t *testing.T, name string, contents []byte) string {
	t.Helper()

	path := t.TempDir() + "/" + name
	require.NoError(t, os.WriteFile(path, contents, 0o600))
	return path
}

func findClusterLinkSubcommand(t *testing.T, command *cli.Command, name string) *cli.Command {
	t.Helper()

	for _, subcommand := range command.Subcommands {
		if subcommand.Name == name {
			return subcommand
		}
	}
	require.FailNow(t, "subcommand not found", name)
	return nil
}
