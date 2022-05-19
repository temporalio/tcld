package app

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/api/temporalcloudapi/namespace/v1"
	"github.com/temporalio/tcld/api/temporalcloudapi/namespaceservice/v1"
	"github.com/temporalio/tcld/api/temporalcloudapi/namespaceservicemock/v1"
	"github.com/temporalio/tcld/api/temporalcloudapi/request/v1"
	"github.com/urfave/cli/v2"
)

func TestNamespace(t *testing.T) {
	suite.Run(t, new(NamespaceTestSuite))
}

type NamespaceTestSuite struct {
	suite.Suite
	cliApp      *cli.App
	mockCtrl    *gomock.Controller
	mockService *namespaceservicemock.MockNamespaceServiceClient
}

func (s *NamespaceTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockService = namespaceservicemock.NewMockNamespaceServiceClient(s.mockCtrl)
	out, err := NewNamespaceCommand(func(ctx *cli.Context) (*NamespaceClient, error) {
		return &NamespaceClient{
			ctx:    context.TODO(),
			client: s.mockService,
		}, nil
	})
	s.Require().NoError(err)
	s.cliApp = &cli.App{
		Name:     "test",
		Commands: []*cli.Command{out.Command},
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
				SearchAttributes: map[string]namespace.NamespaceSpec_SearchAttributeType{
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
		args:      []string{"n", "ca", "set", "-n", ns, "--ca-certificate", "cert2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.State = namespace.STATE_UPDATING },
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
						SearchAttributes: map[string]namespace.NamespaceSpec_SearchAttributeType{
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
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.State = namespace.STATE_UPDATING },
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "add", "-n", ns, "--sa", "attr1=Text"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectErr: true,
	}, {
		args:      []string{"n", "sa", "add", "-n", ns, "--sa", "attr1=Text"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.Spec.SearchAttributes = nil },
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.SearchAttributes = map[string]namespace.NamespaceSpec_SearchAttributeType{
				"attr1": namespace.SEARCH_ATTRIBUTE_TYPE_TEXT,
			}
		},
	}, {
		args: []string{"n", "sa", "add", "-n", ns, "--sa", "attr2=Text",
			"--sa", "attr3=Int", "--resource-version", "ver2"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) {},
		expectUpdate: func(r *namespaceservice.UpdateNamespaceRequest) {
			r.Spec.SearchAttributes = map[string]namespace.NamespaceSpec_SearchAttributeType{
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
						SearchAttributes: map[string]namespace.NamespaceSpec_SearchAttributeType{
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
		args:      []string{"n", "sa", "rn", "-n", ns, "--existing-name", "attr1", "--new-name", "attr3"},
		expectGet: func(g *namespaceservice.GetNamespaceResponse) { g.Namespace.State = namespace.STATE_UPDATING },
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
						SearchAttributes: map[string]namespace.NamespaceSpec_SearchAttributeType{
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
