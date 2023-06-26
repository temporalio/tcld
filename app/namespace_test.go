package app

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/temporalio/tcld/protogen/api/auth/v1"
	"github.com/temporalio/tcld/protogen/api/authservice/v1"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/namespace/v1"
	"github.com/temporalio/tcld/protogen/api/namespaceservice/v1"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	authservicemock "github.com/temporalio/tcld/protogen/apimock/authservice/v1"
	namespaceservicemock "github.com/temporalio/tcld/protogen/apimock/namespaceservice/v1"
	"github.com/urfave/cli/v2"
)

func TestNamespace(t *testing.T) {
	suite.Run(t, new(NamespaceTestSuite))
}

type NamespaceTestSuite struct {
	suite.Suite
	cliApp          *cli.App
	mockCtrl        *gomock.Controller
	mockService     *namespaceservicemock.MockNamespaceServiceClient
	mockAuthService *authservicemock.MockAuthServiceClient
}

func (s *NamespaceTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockService = namespaceservicemock.NewMockNamespaceServiceClient(s.mockCtrl)
	s.mockAuthService = authservicemock.NewMockAuthServiceClient(s.mockCtrl)
	out, err := NewNamespaceCommand(func(ctx *cli.Context) (*NamespaceClient, error) {
		return &NamespaceClient{
			ctx:        context.TODO(),
			client:     s.mockService,
			authClient: s.mockAuthService,
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
			args:      []string{"n", "ucs", "-n", ns, "-endpoint", "fakehost:9999"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CodecSpec = &namespace.CodecServerPropertySpec{Endpoint: "fakehost:9999"}
			},
		},
		{
			args:      []string{"n", "ucs", "-n", ns, "-e", "fakehost:9999", "--pass-access-token"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CodecSpec = &namespace.CodecServerPropertySpec{
					Endpoint:        "fakehost:9999",
					PassAccessToken: true,
				}
			},
		},
		{
			args:      []string{"n", "ucs", "-n", ns, "-e", "fakehost:9999", "--pat", "--include-credentials"},
			expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
			expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
				r.Spec.CodecSpec = &namespace.CodecServerPropertySpec{
					Endpoint:           "fakehost:9999",
					PassAccessToken:    true,
					IncludeCredentials: true,
				}
			},
		},
		// {
		// 	args:      []string{"n", "ucs", "-n", ns, "-e", ""},
		// 	expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		// 	expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
		// 		r.Spec.CodecSpec = &namespace.CodecServerPropertySpec{
		// 			Endpoint: "fakehost:9999",
		// 		}
		// 	},
		// },
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
	}, nil)
	s.NoError(s.RunCmd(
		"namespace", "create",
		"--namespace", "ns1",
		"--region", "us-west-2",
		"--ca-certificate", "cert1",
		"--certificate-filter-input", "{ \"filters\": [ { \"commonName\": \"test1\" } ] }",
		"--search-attribute", "testsearchattribute=Keyword",
		"--user-namespace-permission", "testuser@testcompany.com=Read",
	))
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
