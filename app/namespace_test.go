package app

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/temporalio/tcld/protogen/api/cloud/operation/v1"
	"github.com/temporalio/tcld/protogen/api/common/v1"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"
	"github.com/temporalio/tcld/protogen/api/cloud/cloudservice/v1"
	cloudNamespace "github.com/temporalio/tcld/protogen/api/cloud/namespace/v1"
	cloudSink "github.com/temporalio/tcld/protogen/api/cloud/sink/v1"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/namespace/v1"
	"github.com/temporalio/tcld/protogen/api/namespaceservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	authservicemock "github.com/temporalio/tcld/protogen/apimock/authservice/v1"
	apimock "github.com/temporalio/tcld/protogen/apimock/cloudservice/v1"
	namespaceservicemock "github.com/temporalio/tcld/protogen/apimock/namespaceservice/v1"
	"github.com/urfave/cli/v2"
)

func TestNamespace(t *testing.T) {
	suite.Run(t, new(NamespaceTestSuite))
}

type NamespaceTestSuite struct {
	suite.Suite
	cliApp             *cli.App
	mockCtrl           *gomock.Controller
	mockService        *namespaceservicemock.MockNamespaceServiceClient
	mockAuthService    *authservicemock.MockAuthServiceClient
	mockCloudApiClient *apimock.MockCloudServiceClient
}

func (s *NamespaceTestSuite) SetupTest() {
	err := toggleFeature(GCPSinkFeatureFlag)
	s.Require().NoError(err)

	s.mockCtrl = gomock.NewController(s.T())
	s.mockService = namespaceservicemock.NewMockNamespaceServiceClient(s.mockCtrl)
	s.mockAuthService = authservicemock.NewMockAuthServiceClient(s.mockCtrl)
	s.mockCloudApiClient = apimock.NewMockCloudServiceClient(s.mockCtrl)

	out, err := NewNamespaceCommand(func(ctx *cli.Context) (*NamespaceClient, error) {
		return &NamespaceClient{
			ctx:            context.TODO(),
			client:         s.mockService,
			authClient:     s.mockAuthService,
			cloudAPIClient: s.mockCloudApiClient,
		}, nil
	})
	s.Require().NoError(err)

	cmds := []*cli.Command{
		out.Command,
	}
	flags := []cli.Flag{
		AutoConfirmFlag,
		IdempotentFlag,
	}

	s.cliApp, _ = NewTestApp(s.T(), cmds, flags)

}

func (s *NamespaceTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *NamespaceTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *NamespaceTestSuite) TestGet() {
	s.Error(s.RunCmd("namespace", "get"))
	s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
		Namespace: "ns1",
	}).Return(nil, errors.New("some error")).Times(1)
	s.Error(s.RunCmd("namespace", "get", "--namespace", "ns1"))

	s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
		Namespace: "ns1",
	}).Return(&namespaceservice.GetNamespaceResponse{
		Namespace: &namespace.Namespace{
			Namespace: "ns1",
			Spec: &namespace.NamespaceSpec{
				AcceptedClientCa: "cert1",
				SearchAttributes: map[string]namespace.SearchAttributeType{
					"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
				},
				RetentionDays: 7,
			},
			State:           namespace.STATE_UPDATING,
			ResourceVersion: "ver1",
		},
	}, nil).Times(1)
	s.NoError(s.RunCmd("namespace", "get", "--namespace", "ns1"))
}

func (s *NamespaceTestSuite) TestList() {

	s.mockService.EXPECT().ListNamespaces(gomock.Any(), &namespaceservice.ListNamespacesRequest{}).
		Return(nil, errors.New("some error")).Times(1)
	s.Error(s.RunCmd("namespace", "list"))

	s.mockService.EXPECT().ListNamespaces(gomock.Any(), &namespaceservice.ListNamespacesRequest{
		PageToken: "",
	}).Return(&namespaceservice.ListNamespacesResponse{
		Namespaces: []string{""},
	}, nil).Times(1)
	s.NoError(s.RunCmd("namespace", "list"))

	s.mockService.EXPECT().ListNamespaces(gomock.Any(), &namespaceservice.ListNamespacesRequest{
		PageToken: "",
	}).Return(&namespaceservice.ListNamespacesResponse{
		Namespaces: []string{"ns1", "ns2"},
	}, nil).Times(1)
	s.NoError(s.RunCmd("namespace", "list"))

	s.mockService.EXPECT().ListNamespaces(gomock.Any(), &namespaceservice.ListNamespacesRequest{
		PageToken: "",
	}).Return(&namespaceservice.ListNamespacesResponse{
		Namespaces:    []string{"ns1", "ns2"},
		NextPageToken: "token1",
	}, nil).Times(1)
	s.mockService.EXPECT().ListNamespaces(gomock.Any(), &namespaceservice.ListNamespacesRequest{
		PageToken: "token1",
	}).Return(&namespaceservice.ListNamespacesResponse{
		Namespaces:    []string{"ns3"},
		NextPageToken: "token2",
	}, nil).Times(1)
	s.mockService.EXPECT().ListNamespaces(gomock.Any(), &namespaceservice.ListNamespacesRequest{
		PageToken: "token2",
	}).Return(&namespaceservice.ListNamespacesResponse{
		Namespaces:    []string{"ns4"},
		NextPageToken: "token3",
	}, nil).Times(1)
	s.mockService.EXPECT().ListNamespaces(gomock.Any(), &namespaceservice.ListNamespacesRequest{
		PageToken: "token3",
	}).Return(&namespaceservice.ListNamespacesResponse{}, nil).Times(1)

	s.NoError(s.RunCmd("namespace", "list"))
}

func (s *NamespaceTestSuite) TestDeleteProtection() {
	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	tests := []struct {
		name         string
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{
			name: "no sub command help",
			args: []string{"namespace", "lifecycle"},
		},
		{
			name: "alias with no args help",
			args: []string{"n", "lc"},
		},
		{
			name:      "no flags",
			args:      []string{"namespace", "lifecycle", "set"},
			expectErr: true,
		},
		{
			name:      "no flag value",
			args:      []string{"namespace", "lifecycle", "set", "enable-delete-protection"},
			expectErr: true,
		},
		{
			name:      "missing string flag",
			args:      []string{"n", "lc", "set", "-n", ns},
			expectErr: true,
		},
		{
			name:      "string flag value missing",
			args:      []string{"n", "lc", "set", "-n", ns, "--edp"},
			expectErr: true,
		},
		{
			name:      "success enable",
			args:      []string{"n", "lc", "set", "-n", ns, "--edp", "true"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.Lifecycle = &namespace.LifecycleSpec{
					EnableDeleteProtection: true,
				}
			},
		},
		{
			name: "success disable",
			args: []string{"n", "lc", "set", "-n", ns, "--edp", "false"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace.Spec.Lifecycle = &namespace.LifecycleSpec{
					EnableDeleteProtection: true,
				}
			},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.Lifecycle = &namespace.LifecycleSpec{
					EnableDeleteProtection: false,
				}
			},
		},
		{
			name: "no change already enabled",
			args: []string{"n", "lc", "set", "-n", ns, "--edp", "true"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace.Spec.Lifecycle = &namespace.LifecycleSpec{
					EnableDeleteProtection: true,
				}
			},
			expectErr: true,
		},
		{
			name: "no change already enabled, idempotent",
			args: []string{"--idempotent", "n", "lc", "set", "-n", ns, "--edp", "true"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace.Spec.Lifecycle = &namespace.LifecycleSpec{
					EnableDeleteProtection: true,
				}
			},
			expectErr: false,
		},
		{
			name:      "no change already disabled",
			args:      []string{"n", "lc", "set", "-n", ns, "--edp", "false"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectErr: true,
		},
		{
			name: "missing namespace",
			args: []string{"n", "lc", "set", "-n", ns, "--edp", "true"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = nil
			},
			expectErr: true,
		},
		{
			name: "get lifecycle success",
			args: []string{"n", "lc", "get", "-n", ns},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace.Spec.Lifecycle = &namespace.LifecycleSpec{
					EnableDeleteProtection: true,
				}
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
						AuthMethod:    namespace.AUTH_METHOD_RESTRICTED,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateAuthMethod() {
	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	tests := []struct {
		name         string
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{
			name: "help",
			args: []string{"namespace", "auth-method"},
		},
		{
			name:      "no args",
			args:      []string{"namespace", "auth-method", "set"},
			expectErr: true,
		},
		{
			name:      "alias with no args",
			args:      []string{"n", "am", "set"},
			expectErr: true,
		},
		{
			name:      "invalid auth method",
			args:      []string{"n", "am", "set", "-n", ns, "--auth-method", "invalid"},
			expectErr: true,
		},
		{
			name:      "no change",
			args:      []string{"n", "am", "set", "-n", ns, "--auth-method", AuthMethodRestricted},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectErr: true,
		},
		{
			name:      "success",
			args:      []string{"n", "am", "set", "-n", ns, "--auth-method", AuthMethodMTLS},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.AuthMethod = namespace.AUTH_METHOD_MTLS
			},
		},
		{
			name: "missing namespace",
			args: []string{"n", "am", "set", "-n", ns, "--auth-method", AuthMethodMTLS},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = nil
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
						AuthMethod:    namespace.AUTH_METHOD_RESTRICTED,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestGetAuthMethod() {

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)

	tests := []struct {
		name      string
		args      []string
		expectGet morphGetResp
		expectErr bool
	}{
		{
			name: "help",
			args: []string{"namespace", "auth-method"},
		},
		{
			name:      "no args",
			args:      []string{"namespace", "auth-method", "get"},
			expectErr: true,
		},
		{
			name:      "alias with no args",
			args:      []string{"n", "am", "get"},
			expectErr: true,
		},
		{
			name:      "success",
			args:      []string{"n", "am", "get", "-n", ns},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectErr: false,
		},
		{
			name: "no namespace found",
			args: []string{"n", "am", "get", "-n", ns},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = nil
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						AuthMethod:       namespace.AUTH_METHOD_MTLS,
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 10,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateCA() {

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	path := "cafile"
	s.NoError(os.WriteFile(path, []byte("cert2"), 0644))
	defer os.Remove(path)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{{
		args: []string{"namespace", "accepted-client-ca"},
	}, {
		args:      []string{"namespace", "accepted-client-ca", "set"},
		expectErr: true,
	}, {
		args:      []string{"namespace", "accepted-client-ca", "set", "--namespace", ns},
		expectErr: true,
	}, {
		args:      []string{"n", "ca", "set", "-n", ns, "--ca-certificate", "cert1"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		args:      []string{"n", "ca", "set", "-n", ns, "--ca-certificate", "cert2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { *g = namespaceservice.GetNamespaceResponse{} },
		expectErr: true,
	}, {
		args:      []string{"n", "ca", "set", "-n", ns, "--ca-certificate", "cert2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = "cert2"
		},
	}, {
		args:      []string{"n", "ca", "set", "-n", ns, "--ca-certificate", "cert2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.Spec.AcceptedClientCa = "" },
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = "cert2"
		},
	}, {
		args:      []string{"n", "ca", "set", "-n", ns, "--ca-certificate-file", path},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = base64.StdEncoding.EncodeToString([]byte("cert2"))
		},
	}, {
		args:      []string{"n", "ca", "set", "-n", ns, "--ca-certificate-file", "nonexistingfile"},
		expectErr: true,
	}, {
		args:      []string{"n", "ca", "set", "-n", ns, "-c", "cert2", "--resource-version", "ver2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = "cert2"
			r.ResourceVersion = "ver2"
		},
	}}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateRemoveCA() {

	cert1raw, err := generateRootX509CAForTest()
	s.NoError(err)
	cert2raw, err := generateRootX509CAForTest()
	s.NoError(err)
	cert3raw, err := generateRootX509CAForTest()
	s.NoError(err)

	cert1 := base64.StdEncoding.EncodeToString([]byte(cert1raw))
	cert2 := base64.StdEncoding.EncodeToString([]byte(cert2raw))
	cert12 := base64.StdEncoding.EncodeToString([]byte(cert1raw + "\n" + cert2raw))
	cert3 := base64.StdEncoding.EncodeToString([]byte(cert3raw))

	cs, err := parseCertificates(cert2)
	s.NoError(err)
	cert2fingerprint := cs[0].Fingerprint

	cs, err = parseCertificates(cert3)
	s.NoError(err)
	cert3fingerprint := cs[0].Fingerprint

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	path := "cafile"
	s.NoError(os.WriteFile(path, []byte(cert2raw+"\n"), 0644))
	defer os.Remove(path)

	tests := []struct {
		name         string
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{{
		name:      "err no cmd",
		args:      []string{"namespace", "accepted-client-ca", "remove"},
		expectErr: true,
	}, {
		name:      "err no cert",
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		args:      []string{"namespace", "accepted-client-ca", "remove", "--namespace", ns},
		expectErr: true,
	}, {
		name:      "remove 1st cert",
		args:      []string{"n", "ca", "remove", "-n", ns, "--ca-certificate", cert1},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert2
		},
	}, {
		name:      "remove 2nd cert",
		args:      []string{"n", "ca", "r", "-n", ns, "--ca-certificate", cert2},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert1
		},
	}, {
		name:      "remove unknown cert",
		args:      []string{"n", "ca", "r", "-n", ns, "--ca-certificate", cert3},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		name: "err empty namespace",
		args: []string{"n", "ca", "remove", "-n", ns, "--ca-certificate", cert2},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {
			*g = namespaceservice.GetNamespaceResponse{}
		},
		expectErr: true,
	}, {
		name:      "empty cert - remove 1 cert",
		args:      []string{"n", "ca", "r", "-n", ns, "--ca-certificate", cert2},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.Spec.AcceptedClientCa = "" },
		expectErr: true,
	}, {
		name:      "remove 1 cert from path",
		args:      []string{"n", "ca", "r", "-n", ns, "--ca-certificate-file", path},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert1
		},
	}, {
		name:      "err remove from nonexistent path",
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		args:      []string{"n", "ca", "r", "-n", ns, "--ca-certificate-file", "nonexistingfile"},
		expectErr: true,
	}, {
		name:      "remove fingerprint",
		args:      []string{"n", "ca", "r", "-n", ns, "--ca-certificate-fingerprint", cert2fingerprint},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert1
		},
	}, {
		name:      "err remove unknown fingerprint",
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		args:      []string{"n", "ca", "r", "-n", ns, "--fp", cert3fingerprint},
		expectErr: true,
	}, {
		name:      "custom resource version",
		args:      []string{"n", "ca", "r", "-n", ns, "-c", cert2, "--resource-version", "ver2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert1
			r.ResourceVersion = "ver2"
		},
	}}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: cert12,
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateAddCA() {

	cert1raw, err := generateRootX509CAForTest()
	s.NoError(err)
	cert2raw, err := generateRootX509CAForTest()
	s.NoError(err)

	cert1 := base64.StdEncoding.EncodeToString([]byte(cert1raw))
	cert2 := base64.StdEncoding.EncodeToString([]byte(cert2raw))
	cert12 := base64.StdEncoding.EncodeToString([]byte(cert1raw + "\n" + cert2raw))

	s.NoError(err)

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	path := "cafile"
	s.NoError(os.WriteFile(path, []byte(cert2raw+"\n"), 0644))
	defer os.Remove(path)

	tests := []struct {
		name         string
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{{
		name:      "err no cmd",
		args:      []string{"namespace", "accepted-client-ca", "add"},
		expectErr: true,
	}, {
		name:      "err no cert",
		args:      []string{"namespace", "accepted-client-ca", "add", "--namespace", ns},
		expectErr: true,
	}, {
		name:      "err same cert",
		args:      []string{"n", "ca", "add", "-n", ns, "--ca-certificate", cert1},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		name: "err empty namespace",
		args: []string{"n", "ca", "add", "-n", ns, "--ca-certificate", cert2},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {
			*g = namespaceservice.GetNamespaceResponse{}
		},
		expectErr: true,
	}, {
		name:      "add 1 cert",
		args:      []string{"n", "ca", "add", "-n", ns, "--ca-certificate", cert2},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert12
		},
	}, {
		name:      "empty cert - add 1 cert",
		args:      []string{"n", "ca", "add", "-n", ns, "--ca-certificate", cert2},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.Spec.AcceptedClientCa = "" },
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert2
		},
	}, {
		name:      "add 1 cert from path",
		args:      []string{"n", "ca", "add", "-n", ns, "--ca-certificate-file", path},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert12
		},
	}, {
		name:      "err from nonexistent path",
		args:      []string{"n", "ca", "add", "-n", ns, "--ca-certificate-file", "nonexistingfile"},
		expectErr: true,
	}, {
		name:      "custom resource version",
		args:      []string{"n", "ca", "add", "-n", ns, "-c", cert2, "--resource-version", "ver2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.AcceptedClientCa = cert12
			r.ResourceVersion = "ver2"
		},
	}}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: cert1,
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateAddSearchAttrs() {

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{{
		args: []string{"namespace", "search-attributes"},
	}, {
		args:      []string{"namespace", "search-attributes", "add"},
		expectErr: true,
	}, {
		args:      []string{"namespace", "search-attributes", "add", "--namespace", ns},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "add", "-n", ns, "--search-attribute", "attr1"},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "add", "-n", ns, "--search-attribute", "attr1=InvalidType"},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "add", "-n", ns, "--sa", "attr1=Text"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "add", "-n", ns, "--sa", "attr1=Text"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.Spec.SearchAttributes = nil },
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.SearchAttributes = map[string]namespace.SearchAttributeType{
				"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_TEXT,
			}
		},
	}, {
		args: []string{"n", "sa", "add", "-n", ns, "--sa", "attr2=Text",
			"--sa", "attr3=Int", "--resource-version", "ver2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.SearchAttributes = map[string]namespace.SearchAttributeType{
				"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
				"attr2": namespace.SEARCH_ATTRIBUTE_TYPE_TEXT,
				"attr3": namespace.SEARCH_ATTRIBUTE_TYPE_INT,
			}
			r.ResourceVersion = "ver2"
		},
	}}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateRemoveSearchAttrs() {

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{{
		args: []string{"namespace", "search-attributes"},
	}, {
		args:      []string{"namespace", "search-attributes", "remove"},
		expectErr: true,
	}, {
		args:      []string{"namespace", "search-attributes", "remove", "--namespace", ns},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "remove", "-n", ns, "--sa", "unknown"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "remove", "-n", ns, "--sa", "attr1"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.SearchAttributes = map[string]namespace.SearchAttributeType{}
		},
	}}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateRenameSearchAttrs() {

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphRenameReq func(*namespaceservice.RenameCustomSearchAttributeRequest)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectRename morphRenameReq
	}{{
		args:      []string{"namespace", "search-attributes", "rename"},
		expectErr: true,
	}, {
		args:      []string{"namespace", "search-attributes", "rename", "--namespace", ns},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "rn", "-n", ns, "--existing-name", "attr1"},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "rn", "-n", ns, "--existing-name", "unknown", "--new-name", "attr3"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "rn", "-n", ns, "--existing-name", "attr1", "--new-name", "attr2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "rn", "-n", ns, "--existing-name", "attr1", "--new-name", "attr3"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectRename: func(r *namespaceservice.RenameCustomSearchAttributeRequest) {
			r.NewCustomSearchAttributeName = "attr3"
		},
	}, {
		args:      []string{"n", "sa", "rn", "-n", ns, "--existing-name", "attr1", "--new-name", "attr3", "--resource-version", "ver2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectRename: func(r *namespaceservice.RenameCustomSearchAttributeRequest) {
			r.NewCustomSearchAttributeName = "attr3"
			r.ResourceVersion = "ver2"
		},
	}}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
							"attr2": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectRename != nil {
				req := namespaceservice.RenameCustomSearchAttributeRequest{
					Namespace:                         ns,
					ExistingCustomSearchAttributeName: "attr1",
					ResourceVersion:                   getResp.Namespace.ResourceVersion,
				}
				tc.expectRename(&req)
				s.mockService.EXPECT().RenameCustomSearchAttribute(gomock.Any(), &req).
					Return(&namespaceservice.RenameCustomSearchAttributeResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestImportCertificateFilters() {
	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	path := "certificatefilter"
	s.NoError(os.WriteFile(path, []byte(`{ "filters": [ { "commonName": "test1" } ] }`), 0644))
	defer os.Remove(path)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{

			args: []string{"namespace", "certificate-filters"},
		},
		{
			args:      []string{"namespace", "certificate-filters", "import"},
			expectErr: true,
		},
		{
			args:      []string{"namespace", "certificate-filters", "import", "--namespace", ns},
			expectErr: true,
		},
		{
			args:      []string{"n", "cf", "imp", "-n", ns, "--certificate-filter-file", path},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CertificateFilters = []*namespace.CertificateFilterSpec{{CommonName: "test1"}}
			},
		},
		{
			args:      []string{"n", "cf", "imp", "-n", ns, "--certificate-filter-input", `{ "filters": [ { "commonName": "test1" } ] }`},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CertificateFilters = []*namespace.CertificateFilterSpec{{CommonName: "test1"}}
			},
		},
		{
			args:      []string{"n", "cf", "imp", "-n", ns, "--certificate-filter-file", "nonexistentfile"},
			expectErr: true,
		},
		{
			args:      []string{"n", "cf", "imp", "-n", ns, "--file", "certificatefilter", "--resource-version", "ver2"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CertificateFilters = []*namespace.CertificateFilterSpec{{CommonName: "test1"}}
				r.ResourceVersion = "ver2"
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
						CertificateFilters: []*namespace.CertificateFilterSpec{
							{
								CommonName: "test0",
							},
						},
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestExportCertificateFilters() {
	path := "certificatefilter"
	defer os.Remove(path)

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)

	tests := []struct {
		args      []string
		expectGet morphGetResp
		expectErr bool
	}{
		{
			args: []string{"namespace", "certificate-filters"},
		},
		{
			args:      []string{"namespace", "certificate-filters", "export"},
			expectErr: true,
		},
		{
			args:      []string{"namespace", "certificate-filters", "export", "--namespace", ns},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		},
		{
			args:      []string{"namespace", "certificate-filters", "export", "--namespace", ns, "-f", path},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays:      7,
						CertificateFilters: []*namespace.CertificateFilterSpec{{CommonName: "test1"}},
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}

			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestAddCertificateFilters() {
	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	path := "certificatefilter"
	s.NoError(os.WriteFile(path, []byte(`{ "filters": [ { "commonName": "test1" } ] }`), 0644))
	defer os.Remove(path)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{

			args: []string{"namespace", "certificate-filters"},
		},
		{
			args:      []string{"namespace", "certificate-filters", "add"},
			expectErr: true,
		},
		{
			args:      []string{"namespace", "certificate-filters", "add", "--namespace", ns},
			expectErr: true,
		},
		{
			args:      []string{"n", "cf", "a", "-n", ns, "--certificate-filter-file", path},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CertificateFilters = []*namespace.CertificateFilterSpec{{CommonName: "test1"}}
			},
		},
		{
			args:      []string{"n", "cf", "a", "-n", ns, "--certificate-filter-input", `{ "filters": [ { "commonName": "test1" } ] }`},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CertificateFilters = []*namespace.CertificateFilterSpec{{CommonName: "test1"}}
			},
		},
		{
			args:      []string{"n", "cf", "a", "-n", ns, "--certificate-filter-file", "nonexistentfile"},
			expectErr: true,
		},
		{
			args:      []string{"n", "cf", "a", "-n", ns, "--file", "certificatefilter", "--resource-version", "ver2"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CertificateFilters = []*namespace.CertificateFilterSpec{{CommonName: "test1"}}
				r.ResourceVersion = "ver2"
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestClearCertificateFilters() {
	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{
			args: []string{"namespace", "certificate-filters"},
		},
		{
			args:      []string{"namespace", "certificate-filters", "clear"},
			expectErr: true,
		},
		{
			args:      []string{"namespace", "certificate-filters", "clear", "--namespace", ns},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CertificateFilters = nil
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays:      7,
						CertificateFilters: []*namespace.CertificateFilterSpec{{CommonName: "test1"}},
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateCodecServer() {
	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	tests := []struct {
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{

			args:      []string{"namespace", "update-codec-server"},
			expectErr: true,
		},
		{
			args:      []string{"namespace", "update-codec-server", "--namespace", ns},
			expectErr: true,
		},
		{
			args:      []string{"n", "ucs", "-n", ns, "-endpoint", "https://fakehost:9999"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CodecSpec = &namespace.CodecServerPropertySpec{Endpoint: "https://fakehost:9999"}
			},
		},
		{
			args:      []string{"n", "ucs", "-n", ns, "-e", "https://fakehost:9999", "--pass-access-token"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CodecSpec = &namespace.CodecServerPropertySpec{
					Endpoint:        "https://fakehost:9999",
					PassAccessToken: true,
				}
			},
		},
		{
			args:      []string{"n", "ucs", "-n", ns, "-e", "https://fakehost:9999", "--pat", "--include-credentials"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CodecSpec = &namespace.CodecServerPropertySpec{
					Endpoint:           "https://fakehost:9999",
					PassAccessToken:    true,
					IncludeCredentials: true,
				}
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 7,
						CertificateFilters: []*namespace.CertificateFilterSpec{
							{
								CommonName: "test0",
							},
						},
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateNamespaceRetention() {

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphUpdateReq func(*namespaceservice.UpdateNamespaceRequest)

	tests := []struct {
		name         string
		args         []string
		expectGet    morphGetResp
		expectErr    bool
		expectUpdate morphUpdateReq
	}{
		{
			name: "displays help",
			args: []string{"namespace", "retention"},
		},
		{
			name:      "missing flags",
			args:      []string{"namespace", "retention", "set"},
			expectErr: true,
		},
		{
			name:      "missing retention-days flag",
			args:      []string{"namespace", "retention", "set", "--namespace", ns},
			expectErr: true,
		},
		{
			name:      "happy path",
			args:      []string{"namespace", "retention", "set", "-namespace", ns, "-retention-days", "7"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.RetentionDays = 7
			},
			expectErr: false,
		},
		{
			name:      "aliases",
			args:      []string{"n", "r", "s", "-n", ns, "-rd", "7"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.RetentionDays = 7
			},
			expectErr: false,
		},
		{
			name:      "invalid day negative",
			args:      []string{"namespace", "retention", "set", "-namespace", ns, "-retention-days", "-7"},
			expectErr: true,
		},
		{
			name:      "invalid day 0",
			args:      []string{"namespace", "retention", "set", "-namespace", ns, "-retention-days", "0"},
			expectErr: true,
		},
		{
			name: "no namespace found",
			args: []string{"namespace", "retention", "set", "-namespace", ns, "-retention-days", "7"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = nil
			},
			expectErr: true,
		},
		{
			name:      "retention unchanged",
			args:      []string{"namespace", "retention", "set", "-namespace", ns, "-retention-days", "10"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 10,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectUpdate != nil {
				spec := *(getResp.Namespace.Spec)
				req := namespaceservice.UpdateNamespaceRequest{
					Namespace:       ns,
					Spec:            &spec,
					ResourceVersion: getResp.Namespace.ResourceVersion,
				}
				tc.expectUpdate(&req)
				s.mockService.EXPECT().UpdateNamespace(gomock.Any(), &req).
					Return(&namespaceservice.UpdateNamespaceResponse{
						RequestStatus: &request.RequestStatus{},
					}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestGetNamespaceRetention() {

	ns := "ns1"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)

	tests := []struct {
		name      string
		args      []string
		expectGet morphGetResp
		expectErr bool
	}{
		{
			name: "displays help",
			args: []string{"namespace", "retention"},
		},
		{
			name:      "missing flags",
			args:      []string{"namespace", "retention", "get"},
			expectErr: true,
		},
		{
			name:      "happy path",
			args:      []string{"namespace", "retention", "get", "-namespace", ns},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectErr: false,
		},
		{
			name:      "aliases",
			args:      []string{"n", "r", "g", "-n", ns},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectErr: false,
		},
		{
			name: "no namespace found",
			args: []string{"namespace", "retention", "set", "-namespace", ns, "-retention-days", "7"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = nil
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						AcceptedClientCa: "cert1",
						SearchAttributes: map[string]namespace.SearchAttributeType{
							"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_BOOL,
						},
						RetentionDays: 10,
					},
					State:           namespace.STATE_ACTIVE,
					ResourceVersion: "ver1",
				},
			}
			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestCreate() {
	s.Error(s.RunCmd("namespace", "create"))
	s.Error(s.RunCmd("namespace", "create", "--namespace", "ns1"))
	s.Error(s.RunCmd("namespace", "create", "--namespace", "ns1", "--region", "us-west-2"))
	s.Error(s.RunCmd("namespace", "create", "--namespace", "ns1", "--region", "us-west-2", "--auth-method", "api_key_or_mtls"))
	s.Error(s.RunCmd("namespace", "create", "--namespace", "ns1", "--region", "us-west-2", "--auth-method", "invalid"))
	s.mockService.EXPECT().CreateNamespace(gomock.Any(), gomock.Any()).Return(nil, errors.New("create namespace error")).Times(1)
	s.EqualError(s.RunCmd("namespace", "create", "--namespace", "ns1", "--region", "us-west-2", "--ca-certificate", "cert1"), "create namespace error")
	s.mockService.EXPECT().CreateNamespace(gomock.Any(), gomock.Any()).Return(&namespaceservice.CreateNamespaceResponse{
		RequestStatus: &request.RequestStatus{},
	}, nil).AnyTimes()
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "testuser@testcompany.com",
			},
		},
	}, nil).Times(2)
	s.NoError(s.RunCmd(
		"namespace", "create",
		"--namespace", "ns1",
		"--region", "us-west-2",
		"--ca-certificate", "cert1",
		"--certificate-filter-input", "{ \"filters\": [ { \"commonName\": \"test1\" } ] }",
		"--search-attribute", "testsearchattribute=Keyword",
		"--user-namespace-permission", "testuser@testcompany.com=Read",
	))
	s.NoError(s.RunCmd(
		"namespace", "create",
		"--namespace", "ns1",
		"--region", "us-west-2",
		"--auth-method", "api_key",
		"--search-attribute", "testsearchattribute=Keyword",
		"--user-namespace-permission", "testuser@testcompany.com=Read",
	))
}

func (s *NamespaceTestSuite) TestCreateWithCodec() {
	s.mockService.EXPECT().CreateNamespace(gomock.Any(), gomock.Any()).Return(&namespaceservice.CreateNamespaceResponse{
		RequestStatus: &request.RequestStatus{},
	}, nil).AnyTimes()
	s.mockAuthService.EXPECT().GetUser(gomock.Any(), gomock.Any()).Return(&authservice.GetUserResponse{
		User: &auth.User{
			Id: "test-user-id",
			Spec: &auth.UserSpec{
				Email: "testuser@testcompany.com",
			},
		},
	}, nil).AnyTimes()
	s.NoError(s.RunCmd(
		"namespace", "create",
		"--namespace", "ns1",
		"--region", "us-west-2",
		"--ca-certificate", "cert1",
		"--certificate-filter-input", "{ \"filters\": [ { \"commonName\": \"test1\" } ] }",
		"--search-attribute", "testsearchattribute=Keyword",
		"--user-namespace-permission", "testuser@testcompany.com=Read",
		"--endpoint", "https://test-endpoint.com", "--pass-access-token", "--include-credentials", "false",
	))

	err := s.RunCmd(
		"namespace", "create",
		"--namespace", "ns1",
		"--region", "us-west-2",
		"--ca-certificate", "cert1",
		"--certificate-filter-input", "{ \"filters\": [ { \"commonName\": \"test1\" } ] }",
		"--search-attribute", "testsearchattribute=Keyword",
		"--user-namespace-permission", "testuser@testcompany.com=Read",
		"--endpoint", "http://test-endpoint.com", "--pass-access-token",
	)
	s.Error(err)
	s.ErrorContains(err, "field Endpoint has to use https")

	err = s.RunCmd(
		"namespace", "create",
		"--namespace", "ns1",
		"--region", "us-west-2",
		"--ca-certificate", "cert1",
		"--certificate-filter-input", "{ \"filters\": [ { \"commonName\": \"test1\" } ] }",
		"--search-attribute", "testsearchattribute=Keyword",
		"--user-namespace-permission", "testuser@testcompany.com=Read",
		"--pass-access-token",
	)
	s.Error(err)
	s.ErrorContains(err, "pass-access-token or include-credentials cannot be specified when codec endpoint is not specified")
}

func (s *NamespaceTestSuite) TestDelete() {
	s.Error(s.RunCmd("namespace", "delete"))
	s.mockService.EXPECT().GetNamespace(gomock.Any(), gomock.Any()).Return(&namespaceservice.GetNamespaceResponse{
		Namespace: &namespace.Namespace{
			Namespace: "ns1",
		},
	}, nil).Times(1)
	s.mockService.EXPECT().DeleteNamespace(gomock.Any(), gomock.Any()).Return(&namespaceservice.DeleteNamespaceResponse{
		RequestStatus: &request.RequestStatus{},
	}, nil).Times(1)
	s.NoError(s.RunCmd("namespace", "delete", "--namespace", "ns1"))
}

func (s *NamespaceTestSuite) TestCreateExportS3Sink() {
	ns := "testNamespace"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphCreateSinkReq func(*cloudservice.CreateNamespaceExportSinkRequest)

	tests := []struct {
		name          string
		args          []string
		expectGet     morphGetResp
		expectRequest morphCreateSinkReq
		expectErr     bool
		expectErrMsg  string
	}{
		{
			name:      "create export sink",
			args:      []string{"namespace", "es", "s3", "create", "--namespace", ns, "--sink-name", "sink1", "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectRequest: func(r *cloudservice.CreateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: true,
					S3: &cloudSink.S3Spec{
						RoleName:     "TestRole",
						BucketName:   "testBucket",
						Region:       "us-west-2",
						AwsAccountId: "123456789012",
					},
				}
			},
		},
		{
			name:         "create export sink with invalid role arn",
			args:         []string{"namespace", "es", "s3", "create", "--namespace", ns, "--sink-name", "sink1", "--role-arn", "testRole", "--s3-bucket-name", "testBucket"},
			expectErr:    true,
			expectErrMsg: "invalid assumed role: testRole",
		},
		{
			name: "create export sink with invalid namespace",
			args: []string{"namespace", "es", "s3", "create", "--namespace", ns, "--sink-name", "sink1", "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = &namespace.Namespace{
					Namespace: "",
					Spec: &namespace.NamespaceSpec{
						RegionId: &common.RegionID{
							Name:     "us-west-2",
							Provider: common.CLOUD_PROVIDER_AWS,
						},
					},
				}
			},
			expectErr:    true,
			expectErrMsg: "unable to get namespace: invalid namespace returned by server",
		},
		{
			name: "uses region when provided as arg",
			args: []string{"namespace", "es", "s3", "create", "--namespace", ns, "--sink-name", "sink1", "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket", "--region", "us-east-1"},
			expectRequest: func(r *cloudservice.CreateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: true,
					S3: &cloudSink.S3Spec{
						RoleName:     "TestRole",
						BucketName:   "testBucket",
						Region:       "us-east-1",
						AwsAccountId: "123456789012",
					},
				}
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						RegionId: &common.RegionID{
							Name:     "us-west-2",
							Provider: common.CLOUD_PROVIDER_AWS,
						},
					},
				},
			}

			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectRequest != nil {
				req := cloudservice.CreateNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().CreateNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.CreateNamespaceExportSinkResponse{AsyncOperation: &operation.AsyncOperation{}}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
				s.ErrorContains(err, tc.expectErrMsg)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestGetExportSink() {
	ns := "namespace"
	type morphGetReq func(*cloudservice.GetNamespaceExportSinkRequest)

	tests := []struct {
		name          string
		args          []string
		expectRequest morphGetReq
		expectErr     bool
	}{
		{
			name: "get export sink succeeds",
			args: []string{"namespace", "es", "s3", "get", "--namespace", ns, "--sink-name", "sink1"},
			expectRequest: func(r *cloudservice.GetNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Name = "sink1"
			},
		},
		{
			name: "get export sink succeeds",
			args: []string{"namespace", "es", "gcs", "get", "--namespace", ns, "--sink-name", "sink1"},
			expectRequest: func(r *cloudservice.GetNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Name = "sink1"
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			if tc.expectRequest != nil {
				req := cloudservice.GetNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().GetNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.GetNamespaceExportSinkResponse{Sink: &cloudNamespace.ExportSink{}}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestDeleteNamespaceExportSink() {
	ns := "namespace"
	type morphDeleteReq func(*cloudservice.DeleteNamespaceExportSinkRequest)
	type morphGetSinkResp func(*cloudservice.GetNamespaceExportSinkResponse)

	tests := []struct {
		name                  string
		args                  []string
		expectGetSinkResponse morphGetSinkResp
		expectRequest         morphDeleteReq
		expectErr             bool
		expectErrMsg          string
	}{
		{
			name: "delete export sink succeeds without resource version",
			args: []string{"namespace", "es", "s3", "delete", "--namespace", ns, "--sink-name", "sink1"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {
				r.Sink = &cloudNamespace.ExportSink{
					ResourceVersion: "124214124",
				}
			},
			expectRequest: func(r *cloudservice.DeleteNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Name = "sink1"
				r.ResourceVersion = "124214124"
			},
		},
		{
			name: "delete export succeeds sink with resource version",
			args: []string{"namespace", "es", "s3", "delete", "--namespace", ns, "--sink-name", "sink1", "--resource-version", "999999999"},
			expectRequest: func(r *cloudservice.DeleteNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Name = "sink1"
				r.ResourceVersion = "999999999"
			},
		},
		{
			name: "delete export sink succeeds without resource version",
			args: []string{"namespace", "es", "gcs", "delete", "--namespace", ns, "--sink-name", "sink1"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {
				r.Sink = &cloudNamespace.ExportSink{
					ResourceVersion: "124214124",
				}
			},
			expectRequest: func(r *cloudservice.DeleteNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Name = "sink1"
				r.ResourceVersion = "124214124"
			},
		},
		{
			name: "delete export succeeds sink with resource version",
			args: []string{"namespace", "es", "gcs", "delete", "--namespace", ns, "--sink-name", "sink1", "--resource-version", "999999999"},
			expectRequest: func(r *cloudservice.DeleteNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Name = "sink1"
				r.ResourceVersion = "999999999"
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			if tc.expectGetSinkResponse != nil {
				getSinkResp := cloudservice.GetNamespaceExportSinkResponse{Sink: &cloudNamespace.ExportSink{}}
				tc.expectGetSinkResponse(&getSinkResp)
				s.mockCloudApiClient.EXPECT().GetNamespaceExportSink(gomock.Any(), gomock.Any()).Return(&getSinkResp, nil).Times(1)
			}

			if tc.expectRequest != nil {
				req := cloudservice.DeleteNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().DeleteNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.DeleteNamespaceExportSinkResponse{AsyncOperation: &operation.AsyncOperation{}}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestCreateExportGCSSink() {
	ns := "testNamespace"
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)
	type morphCreateSinkReq func(*cloudservice.CreateNamespaceExportSinkRequest)

	tests := []struct {
		name          string
		args          []string
		expectGet     morphGetResp
		expectRequest morphCreateSinkReq
		expectErr     bool
		expectErrMsg  string
	}{
		{
			name:      "create export sink",
			args:      []string{"namespace", "es", "gcs", "create", "--namespace", ns, "--sink-name", "sink1", "--service-account-email", "testSA@testGcpAccount.iam.gserviceaccount.com", "--gcs-bucket", "testBucket"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectRequest: func(r *cloudservice.CreateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: true,
					Gcs: &cloudSink.GCSSpec{
						SaId:         "testSA",
						GcpProjectId: "testGcpAccount",
						BucketName:   "testBucket",
					},
				}
			},
		},
		{
			name:         "create export sink with invalid service account principal",
			args:         []string{"namespace", "es", "gcs", "create", "--namespace", ns, "--sink-name", "sink1", "--service-account-email", "testSA", "--gcs-bucket", "testBucket"},
			expectErr:    true,
			expectErrMsg: "invalid SA principal: testSA",
		},
		{
			name: "create export sink with invalid namespace",
			args: []string{"namespace", "es", "gcs", "create", "--namespace", ns, "--sink-name", "sink1", "--service-account-email", "testSA@testGcpAccount.iam.gserviceaccount.com", "--gcs-bucket", "testBucket"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = &namespace.Namespace{
					Namespace: "",
					Spec: &namespace.NamespaceSpec{
						RegionId: &common.RegionID{
							Name:     "us-west-2",
							Provider: common.CLOUD_PROVIDER_AWS,
						},
					},
				}
			},
			expectErr:    true,
			expectErrMsg: "unable to get namespace: invalid namespace returned by server",
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			getResp := namespaceservice.GetNamespaceResponse{
				Namespace: &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						RegionId: &common.RegionID{
							Name:     "us-west-2",
							Provider: common.CLOUD_PROVIDER_AWS,
						},
					},
				},
			}

			if tc.expectGet != nil {
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&getResp, nil).Times(1)
			}

			if tc.expectRequest != nil {
				req := cloudservice.CreateNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().CreateNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.CreateNamespaceExportSinkResponse{AsyncOperation: &operation.AsyncOperation{}}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
				s.ErrorContains(err, tc.expectErrMsg)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateExportGCSSink() {
	ns := "sink1"
	type morphGetReq func(*cloudservice.UpdateNamespaceExportSinkRequest)
	type morphGetSinkResp func(*cloudservice.GetNamespaceExportSinkResponse)

	tests := []struct {
		name                  string
		args                  []string
		expectGetSinkResponse morphGetSinkResp
		expectRequest         morphGetReq
		expectErr             bool
		expectErrMsg          string
	}{
		{
			name:                  "update export sink succeeds with no input",
			args:                  []string{"namespace", "es", "gcs", "update", "--namespace", ns, "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
		},
		{
			name:         "update export sink fails with no sink name",
			args:         []string{"namespace", "es", "gcs", "update", "--namespace", ns, "--service-account-email", "testSA@testGcpAccount.iam.gserviceaccount.com", "--gcs-bucket", "testBucket", "--enabled", "true"},
			expectErr:    true,
			expectErrMsg: "Required flag \"sink-name\" not set",
		},
		{
			name:                  "update export sink fails with not valid enabled value",
			args:                  []string{"namespace", "es", "gcs", "update", "--namespace", ns, "--service-account-email", "testSA@testGcpAccount.iam.gserviceaccount.com", "--gcs-bucket", "testBucket", "--sink-name", "testSink", "--enabled", ""},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectErr:             true,
			expectErrMsg:          "invalid value for enabled flag",
		},
		{
			name:                  "update export sink succeeds with enable flag",
			args:                  []string{"namespace", "es", "gcs", "update", "--namespace", ns, "--enabled", "false", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					Gcs: &cloudSink.GCSSpec{
						SaId:         "testSA",
						GcpProjectId: "testGcpAccount",
						BucketName:   "testBucket",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
		{
			name:                  "update export sink succeeds with sa principal and enabled flag",
			args:                  []string{"namespace", "es", "gcs", "update", "--namespace", ns, "--enabled", "false", "--service-account-email", "newTestSA@newTestGcpAccount.iam.gserviceaccount.com", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					Gcs: &cloudSink.GCSSpec{
						SaId:         "newTestSA",
						GcpProjectId: "newTestGcpAccount",
						BucketName:   "testBucket",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
		{
			name:                  "update export sink succeeds with sa principal, bucket name and enabled flag",
			args:                  []string{"namespace", "es", "gcs", "update", "--namespace", ns, "--service-account-email", "newTestSA@newTestGcpAccount.iam.gserviceaccount.com", "--gcs-bucket", "newTestBucket", "--enabled", "false", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					Gcs: &cloudSink.GCSSpec{
						SaId:         "newTestSA",
						GcpProjectId: "newTestGcpAccount",
						BucketName:   "newTestBucket",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
		{
			name:                  "update export sink succeeds with sa principal, bucket name and enabled flag",
			args:                  []string{"namespace", "es", "gcs", "update", "--namespace", ns, "--service-account-email", "newTestSA@newTestGcpAccount.iam.gserviceaccount.com", "--gcs-bucket", "newTestBucket", "--enabled", "false", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					Gcs: &cloudSink.GCSSpec{
						SaId:         "newTestSA",
						GcpProjectId: "newTestGcpAccount",
						BucketName:   "newTestBucket",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			if tc.expectGetSinkResponse != nil {
				getSinkResp := cloudservice.GetNamespaceExportSinkResponse{Sink: &cloudNamespace.ExportSink{
					Name: ns,
					Spec: &cloudNamespace.ExportSinkSpec{
						Name:    ns,
						Enabled: true,
						Gcs: &cloudSink.GCSSpec{
							SaId:         "testSA",
							GcpProjectId: "testGcpAccount",
							BucketName:   "testBucket",
						},
					},
					ResourceVersion: "124214124",
				}}
				tc.expectGetSinkResponse(&getSinkResp)
				s.mockCloudApiClient.EXPECT().GetNamespaceExportSink(gomock.Any(), gomock.Any()).Return(&getSinkResp, nil).Times(1)
			}

			if tc.expectRequest != nil {
				req := cloudservice.UpdateNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().UpdateNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.UpdateNamespaceExportSinkResponse{AsyncOperation: &operation.AsyncOperation{}}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
				s.ErrorContains(err, tc.expectErrMsg)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestValidateExportGCPSink() {
	ns := "namespace"
	type morphValidateReq func(*cloudservice.ValidateNamespaceExportSinkRequest)
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)

	tests := []struct {
		name string

		args          []string
		expectRequest morphValidateReq
		expectErr     bool
		expectGet     morphGetResp
	}{
		{
			name: "Validate export gcs sinks succeeds",
			args: []string{"namespace", "es", "gcs", "validate", "--namespace", ns, "--sink-name", "sink1", "--service-account-email", "test-sa@test-gcs.iam.gserviceaccount.com", "--gcs-bucket", "testBucket"},
			expectRequest: func(r *cloudservice.ValidateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name: "sink1",
					Gcs: &cloudSink.GCSSpec{
						SaId:         "test-sa",
						BucketName:   "testBucket",
						GcpProjectId: "test-gcs",
					},
				}
			},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = &namespace.Namespace{
					Namespace: ns,
				}
			},
			expectErr: false,
		},
		{
			name:      "Validate export gcs sinks fails with invalid sa principal",
			args:      []string{"namespace", "es", "gcs", "validate", "--namespace", ns, "--sink-name", "sink1", "--service-account-email", "testSA", "--gcs-bucket", "testBucket"},
			expectErr: true,
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			if tc.expectGet != nil {
				getResp := namespaceservice.GetNamespaceResponse{}
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), gomock.Any()).Return(&getResp, nil).Times(1)
			}

			if tc.expectRequest != nil {
				req := cloudservice.ValidateNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().ValidateNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.ValidateNamespaceExportSinkResponse{}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestValidateExportS3Sink() {
	ns := "namespace"
	type morphValidateReq func(*cloudservice.ValidateNamespaceExportSinkRequest)
	type morphGetResp func(*namespaceservice.GetNamespaceResponse)

	tests := []struct {
		name string

		args          []string
		expectRequest morphValidateReq
		expectErr     bool
		expectGet     morphGetResp
	}{
		{
			name: "Validate export sinks succeeds",
			args: []string{"namespace", "es", "s3", "validate", "--namespace", ns, "--sink-name", "sink1", "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket"},
			expectRequest: func(r *cloudservice.ValidateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name: "sink1",
					S3: &cloudSink.S3Spec{
						RoleName:     "TestRole",
						BucketName:   "testBucket",
						Region:       "us-west-2",
						AwsAccountId: "123456789012",
					},
				}
			},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						RegionId: &common.RegionID{
							Name:     "us-west-2",
							Provider: common.CLOUD_PROVIDER_AWS,
						},
					},
				}
			},
			expectErr: false,
		},
		{
			name:      "Validate export sinks fails with invalid role arn",
			args:      []string{"namespace", "es", "s3", "validate", "--namespace", ns, "--sink-name", "sink1", "--role-arn", "testRole", "--s3-bucket-name", "testBucket"},
			expectErr: true,
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		},
		{
			name: "Validate export sinks succeeds",
			args: []string{"namespace", "es", "s3", "validate", "--namespace", ns, "--sink-name", "sink1", "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket", "--region", "us-east-1"},
			expectRequest: func(r *cloudservice.ValidateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name: "sink1",
					S3: &cloudSink.S3Spec{
						RoleName:     "TestRole",
						BucketName:   "testBucket",
						Region:       "us-east-1",
						AwsAccountId: "123456789012",
					},
				}
			},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {
				g.Namespace = &namespace.Namespace{
					Namespace: ns,
					Spec: &namespace.NamespaceSpec{
						RegionId: &common.RegionID{
							Name:     "us-west-2",
							Provider: common.CLOUD_PROVIDER_AWS,
						},
					},
				}
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			if tc.expectGet != nil {
				getResp := namespaceservice.GetNamespaceResponse{}
				tc.expectGet(&getResp)
				s.mockService.EXPECT().GetNamespace(gomock.Any(), gomock.Any()).Return(&getResp, nil).AnyTimes()
			}
			if tc.expectRequest != nil {
				req := cloudservice.ValidateNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().ValidateNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.ValidateNamespaceExportSinkResponse{}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestListExportSinks() {
	ns := "namespace"
	type morphGetReq func(*cloudservice.GetNamespaceExportSinksRequest)

	tests := []struct {
		name string

		args          []string
		expectRequest morphGetReq
		expectErr     bool
	}{
		{
			name: "list export sinks succeeds",
			args: []string{"namespace", "es", "s3", "list", "--namespace", ns},
			expectRequest: func(r *cloudservice.GetNamespaceExportSinksRequest) {
				r.Namespace = ns
				r.PageSize = 100
			},
		},
		{
			name: "list export sinks succeeds",
			args: []string{"namespace", "es", "gcs", "list", "--namespace", ns},
			expectRequest: func(r *cloudservice.GetNamespaceExportSinksRequest) {
				r.Namespace = ns
				r.PageSize = 100
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			if tc.expectRequest != nil {
				req := cloudservice.GetNamespaceExportSinksRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().GetNamespaceExportSinks(gomock.Any(), &req).
					Return(&cloudservice.GetNamespaceExportSinksResponse{}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestUpdateExportS3Sink() {
	ns := "sink1"
	type morphGetReq func(*cloudservice.UpdateNamespaceExportSinkRequest)
	type morphGetSinkResp func(*cloudservice.GetNamespaceExportSinkResponse)

	tests := []struct {
		name                  string
		args                  []string
		expectGetSinkResponse morphGetSinkResp
		expectRequest         morphGetReq
		expectErr             bool
		expectErrMsg          string
	}{
		{
			name:                  "update export sink succeeds with no input",
			args:                  []string{"namespace", "es", "s3", "update", "--namespace", ns, "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
		},
		{
			name:                  "update export sink succeeds with no updates",
			args:                  []string{"namespace", "es", "s3", "update", "--namespace", ns, "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket", "--enabled", "true", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
		},
		{
			name:         "update export sink fails with no sink name",
			args:         []string{"namespace", "es", "s3", "update", "--namespace", ns, "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket", "--enabled", "true"},
			expectErr:    true,
			expectErrMsg: "Required flag \"sink-name\" not set",
		},
		{
			name:                  "update export sink fails with not valid enabled value",
			args:                  []string{"namespace", "es", "s3", "update", "--namespace", ns, "--role-arn", "arn:aws:iam::123456789012:role/TestRole", "--s3-bucket-name", "testBucket", "--sink-name", "testSink", "--enabled", ""},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectErr:             true,
			expectErrMsg:          "invalid value for enabled flag",
		},
		{
			name:                  "update export sink succeeds with enable flag",
			args:                  []string{"namespace", "es", "s3", "update", "--namespace", ns, "--enabled", "false", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					S3: &cloudSink.S3Spec{
						RoleName:     "TestRole",
						BucketName:   "testBucket",
						Region:       "us-west-2",
						AwsAccountId: "123456789012",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
		{
			name:                  "update export sink succeeds with role arn and enabled flag",
			args:                  []string{"namespace", "es", "s3", "update", "--namespace", ns, "--enabled", "false", "--role-arn", "arn:aws:iam::923456789012:role/newTestRole", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					S3: &cloudSink.S3Spec{
						RoleName:     "newTestRole",
						BucketName:   "testBucket",
						Region:       "us-west-2",
						AwsAccountId: "923456789012",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
		{
			name:                  "update export sink succeeds with role arn, bucket name and enabled flag",
			args:                  []string{"namespace", "es", "s3", "update", "--namespace", ns, "--role-arn", "arn:aws:iam::923456789012:role/newTestRole", "--s3-bucket-name", "newTestBucket", "--enabled", "false", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					S3: &cloudSink.S3Spec{
						RoleName:     "newTestRole",
						BucketName:   "newTestBucket",
						Region:       "us-west-2",
						AwsAccountId: "923456789012",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
		{
			name:                  "update export sink succeeds with role arn, bucket name, kms arn and enabled flag",
			args:                  []string{"namespace", "es", "s3", "update", "--namespace", ns, "--role-arn", "arn:aws:iam::923456789012:role/newTestRole", "--s3-bucket-name", "newTestBucket", "--kms-arn", "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", "--enabled", "false", "--sink-name", "testSink"},
			expectGetSinkResponse: func(r *cloudservice.GetNamespaceExportSinkResponse) {},
			expectRequest: func(r *cloudservice.UpdateNamespaceExportSinkRequest) {
				r.Namespace = ns
				r.Spec = &cloudNamespace.ExportSinkSpec{
					Name:    "sink1",
					Enabled: false,
					S3: &cloudSink.S3Spec{
						RoleName:     "newTestRole",
						BucketName:   "newTestBucket",
						Region:       "us-west-2",
						AwsAccountId: "923456789012",
						KmsArn:       "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
					},
				}
				r.ResourceVersion = "124214124"
			},
		},
	}

	for _, tc := range tests {
		s.Run(strings.Join(tc.args, " "), func() {
			if tc.expectGetSinkResponse != nil {
				getSinkResp := cloudservice.GetNamespaceExportSinkResponse{Sink: &cloudNamespace.ExportSink{
					Name: ns,
					Spec: &cloudNamespace.ExportSinkSpec{
						Name:    ns,
						Enabled: true,
						S3: &cloudSink.S3Spec{
							RoleName:     "TestRole",
							BucketName:   "testBucket",
							Region:       "us-west-2",
							AwsAccountId: "123456789012",
						},
					},
					ResourceVersion: "124214124",
				}}
				tc.expectGetSinkResponse(&getSinkResp)
				s.mockCloudApiClient.EXPECT().GetNamespaceExportSink(gomock.Any(), gomock.Any()).Return(&getSinkResp, nil).Times(1)
			}

			if tc.expectRequest != nil {
				req := cloudservice.UpdateNamespaceExportSinkRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().UpdateNamespaceExportSink(gomock.Any(), &req).
					Return(&cloudservice.UpdateNamespaceExportSinkResponse{AsyncOperation: &operation.AsyncOperation{}}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
				s.ErrorContains(err, tc.expectErrMsg)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *NamespaceTestSuite) TestRemoveNamespaceRegion() {
	ns := "namespace"
	type expectReq func(*cloudservice.DeleteNamespaceRegionRequest)

	tests := []struct {
		name string

		args          []string
		expectRequest expectReq
		expectErr     bool
	}{
		{
			name: "Validate default cloud provider",
			args: []string{"namespace", "delete-region", "--namespace", ns, "--region", "us-west-2"},
			expectRequest: func(r *cloudservice.DeleteNamespaceRegionRequest) {
				r.Namespace = ns
				r.Region = "aws-us-west-2"
				r.ResourceVersion = "ver1"
			},
			expectErr: false,
		},
		{
			name: "Validate GCP cloud provider",
			args: []string{"namespace", "delete-region", "--namespace", ns, "--region", "us-central1", "--cloud-provider", "gcp"},
			expectRequest: func(r *cloudservice.DeleteNamespaceRegionRequest) {
				r.Namespace = ns
				r.Region = "gcp-us-central1"
				r.ResourceVersion = "ver1"
			},
			expectErr: false,
		},
		{
			name:      "Invalid Argument: missing namespace",
			args:      []string{"namespace", "delete-region", "--region", "us-west-2"},
			expectErr: true,
		},
		{
			name:      "Invalid Argument: missing region",
			args:      []string{"namespace", "delete-region", "--namespace", ns},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {

			if tc.expectRequest != nil {
				req := cloudservice.DeleteNamespaceRegionRequest{}
				tc.expectRequest(&req)
				s.mockCloudApiClient.EXPECT().DeleteNamespaceRegion(gomock.Any(), &req).
					Return(&cloudservice.DeleteNamespaceRegionResponse{
						AsyncOperation: &operation.AsyncOperation{Id: tc.name},
					}, nil).Times(1)
			}
			if !tc.expectErr {
				s.mockService.EXPECT().GetNamespace(gomock.Any(), &namespaceservice.GetNamespaceRequest{
					Namespace: ns,
				}).Return(&namespaceservice.GetNamespaceResponse{
					Namespace: &namespace.Namespace{
						Namespace:       ns,
						State:           namespace.STATE_UPDATING,
						ResourceVersion: "ver1",
					},
				}, nil).Times(1)
			}

			err := s.RunCmd(tc.args...)
			if tc.expectErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}
