// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/namespaceservice/v1/service.proto

package namespaceservice

import (
	context "context"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

func init() {
	proto.RegisterFile("api/namespaceservice/v1/service.proto", fileDescriptor_d746e5fd89aff5eb)
}

var fileDescriptor_d746e5fd89aff5eb = []byte{
	// 492 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x95, 0x3f, 0x6f, 0x13, 0x31,
	0x18, 0x87, 0xef, 0x16, 0x06, 0x0b, 0xda, 0xe2, 0x05, 0xa9, 0x48, 0x1e, 0x90, 0xd8, 0xa8, 0x8f,
	0xa4, 0x6c, 0x65, 0x81, 0xf2, 0x67, 0x41, 0x0c, 0x8d, 0x60, 0x60, 0x41, 0x6e, 0xfa, 0x4a, 0x18,
	0x2e, 0x39, 0x63, 0x3b, 0x27, 0x90, 0x90, 0xe0, 0x23, 0x30, 0xf3, 0x09, 0xf8, 0x10, 0x7c, 0x00,
	0xc6, 0x8c, 0x1d, 0xc9, 0x65, 0x61, 0xec, 0x47, 0x40, 0xe5, 0x62, 0xc7, 0xb1, 0xe5, 0x3b, 0xa7,
	0x5b, 0x14, 0x3f, 0xbf, 0xf7, 0x39, 0xdb, 0xef, 0xbd, 0x87, 0xee, 0x32, 0xc1, 0x8b, 0x29, 0x9b,
	0x80, 0x12, 0x6c, 0x0c, 0x0a, 0x64, 0xcd, 0xc7, 0x50, 0xd4, 0x83, 0x62, 0xf5, 0x93, 0x0a, 0x59,
	0xe9, 0x0a, 0xdf, 0x62, 0x82, 0x53, 0x1f, 0xa3, 0xf5, 0x60, 0x9f, 0xc6, 0xf2, 0x12, 0x3e, 0xce,
	0x40, 0xe9, 0xb7, 0x12, 0x94, 0xa8, 0xa6, 0x6a, 0x55, 0x68, 0xf8, 0x6b, 0x07, 0xed, 0xbd, 0x34,
	0xf8, 0xa8, 0xc5, 0x71, 0x8d, 0x76, 0x8f, 0x25, 0x30, 0x0d, 0x76, 0x05, 0x17, 0x34, 0x62, 0xa4,
	0x1e, 0x79, 0xd2, 0x7a, 0xf6, 0xef, 0xa7, 0x07, 0xda, 0x07, 0xba, 0x93, 0x61, 0x85, 0x76, 0x5e,
	0x70, 0xa5, 0xed, 0x92, 0xc2, 0x34, 0x5a, 0x65, 0x13, 0x34, 0xd6, 0x22, 0x99, 0xb7, 0x52, 0x81,
	0x6e, 0x3c, 0x07, 0xd7, 0x79, 0x10, 0xad, 0xb1, 0xc1, 0x19, 0x25, 0x4d, 0xc5, 0xad, 0x71, 0x82,
	0xae, 0xbb, 0x4b, 0xf8, 0x5e, 0x52, 0x05, 0xe3, 0x3b, 0x48, 0xa4, 0xad, 0xae, 0x46, 0xbb, 0xaf,
	0xc4, 0x59, 0xe2, 0x6d, 0x7a, 0x64, 0xff, 0x6d, 0x06, 0x01, 0xeb, 0xfd, 0x91, 0xa3, 0xdb, 0x27,
	0x70, 0x99, 0x39, 0x9e, 0x29, 0x5d, 0x4d, 0x46, 0xc0, 0xe4, 0xf8, 0xdd, 0x23, 0xad, 0x25, 0x3f,
	0x9d, 0x69, 0xc0, 0x47, 0xd1, 0x9a, 0x1d, 0x29, 0xf3, 0x40, 0x0f, 0xaf, 0x16, 0x76, 0x0f, 0xe5,
	0x09, 0x94, 0x90, 0x76, 0x28, 0x1e, 0xd9, 0x7f, 0x28, 0x41, 0xc0, 0x7a, 0x3f, 0xa3, 0xbd, 0xb6,
	0xff, 0x9f, 0x7e, 0x12, 0x95, 0xd4, 0x23, 0x3e, 0xfd, 0x80, 0xfb, 0x5e, 0x95, 0x35, 0x6a, 0xcc,
	0x83, 0x2d, 0x12, 0x5e, 0xa3, 0x3b, 0xde, 0xce, 0x4e, 0x0a, 0xa5, 0x34, 0x15, 0x77, 0x37, 0xdb,
	0x9e, 0x44, 0xd2, 0x66, 0x7d, 0xb4, 0x7f, 0xb3, 0x61, 0xc2, 0x55, 0xb7, 0x9d, 0x99, 0xa4, 0xf6,
	0xd1, 0x7e, 0x75, 0x98, 0x70, 0x5b, 0xeb, 0x72, 0xd8, 0xac, 0xd7, 0x14, 0xee, 0x1e, 0x4b, 0x0e,
	0xd9, 0xdf, 0x5a, 0x41, 0xc0, 0x7a, 0xbf, 0x22, 0xfc, 0x9a, 0x95, 0xdc, 0xdb, 0xf4, 0x30, 0x5a,
	0x29, 0x84, 0x8d, 0xfd, 0x70, 0xab, 0x8c, 0x3b, 0xbe, 0x37, 0x3a, 0xa1, 0x6b, 0x7c, 0x6f, 0x82,
	0xfd, 0xe3, 0xdb, 0xe7, 0xad, 0xf4, 0x0b, 0xba, 0xf9, 0x8c, 0xf1, 0xb2, 0xaa, 0x41, 0xae, 0x5f,
	0xe5, 0xf8, 0xbd, 0x05, 0xac, 0x51, 0x0f, 0xb7, 0x89, 0x18, 0xfb, 0xe3, 0xf7, 0xf3, 0x05, 0xc9,
	0xce, 0x17, 0x24, 0xbb, 0x58, 0x90, 0xfc, 0x5b, 0x43, 0xf2, 0x9f, 0x0d, 0xc9, 0x7f, 0x37, 0x24,
	0x9f, 0x37, 0x24, 0xff, 0xd3, 0x90, 0xfc, 0x6f, 0x43, 0xb2, 0x8b, 0x86, 0xe4, 0xdf, 0x97, 0x24,
	0x9b, 0x2f, 0x49, 0x76, 0xbe, 0x24, 0xd9, 0x9b, 0x07, 0x7a, 0x22, 0x64, 0x49, 0xc7, 0x65, 0x35,
	0x3b, 0x2b, 0x22, 0x1f, 0xec, 0x23, 0xff, 0xbf, 0xd3, 0x6b, 0xff, 0xbf, 0xd8, 0x87, 0xff, 0x02,
	0x00, 0x00, 0xff, 0xff, 0xde, 0x54, 0xaa, 0xf1, 0x23, 0x08, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// NamespaceServiceClient is the client API for NamespaceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type NamespaceServiceClient interface {
	// CreateNamespace creates a new namespace on Temporal cloud.
	CreateNamespace(ctx context.Context, in *CreateNamespaceRequest, opts ...grpc.CallOption) (*CreateNamespaceResponse, error)
	// ListNamespaces lists the names of all known namespaces on Temporal cloud.
	ListNamespaces(ctx context.Context, in *ListNamespacesRequest, opts ...grpc.CallOption) (*ListNamespacesResponse, error)
	// GetNamespaces lists all known namespaces on temporal cloud.
	GetNamespaces(ctx context.Context, in *GetNamespacesRequest, opts ...grpc.CallOption) (*GetNamespacesResponse, error)
	// GetNamespace describes the namespace in detail.
	GetNamespace(ctx context.Context, in *GetNamespaceRequest, opts ...grpc.CallOption) (*GetNamespaceResponse, error)
	// UpdateNamespace updates an existing namespace on Temporal cloud.
	UpdateNamespace(ctx context.Context, in *UpdateNamespaceRequest, opts ...grpc.CallOption) (*UpdateNamespaceResponse, error)
	// RenameCustomSearchAttribute renames an existing custom search attribute for a given namespace on Temporal cloud.
	RenameCustomSearchAttribute(ctx context.Context, in *RenameCustomSearchAttributeRequest, opts ...grpc.CallOption) (*RenameCustomSearchAttributeResponse, error)
	// DeleteNamespace deletes an existing namespace on Temporal cloud.
	DeleteNamespace(ctx context.Context, in *DeleteNamespaceRequest, opts ...grpc.CallOption) (*DeleteNamespaceResponse, error)
	// CreateExportSink creates a new sink under the specified namespace on Temporal cloud
	CreateExportSink(ctx context.Context, in *CreateExportSinkRequest, opts ...grpc.CallOption) (*CreateExportSinkResponse, error)
	// GetExportSink gets the specified sink under the specified namespace on Temporal cloud
	GetExportSink(ctx context.Context, in *GetExportSinkRequest, opts ...grpc.CallOption) (*GetExportSinkResponse, error)
	// DeleteExportSink deletes the specified sink under the specified namespace on Temporal cloud
	DeleteExportSink(ctx context.Context, in *DeleteExportSinkRequest, opts ...grpc.CallOption) (*DeleteExportSinkResponse, error)
	// UpdateExportSink updates the specified sink under the specified namespace on Temporal Cloud
	UpdateExportSink(ctx context.Context, in *UpdateExportSinkRequest, opts ...grpc.CallOption) (*UpdateExportSinkResponse, error)
	// ListExportSinks lists the export sinks under the specified namespace on Temporal Cloud
	ListExportSinks(ctx context.Context, in *ListExportSinksRequest, opts ...grpc.CallOption) (*ListExportSinksResponse, error)
	// ValidateExportSink that could write test file to sink on Temporal Cloud
	ValidateExportSink(ctx context.Context, in *ValidateExportSinkRequest, opts ...grpc.CallOption) (*ValidateExportSinkResponse, error)
	// GetExportSinks retrieves the export sinks under the specified namespace on Temporal Cloud
	GetExportSinks(ctx context.Context, in *GetExportSinksRequest, opts ...grpc.CallOption) (*GetExportSinksResponse, error)
	// FailoverNamespace failovers the namespace from the source_region to the target_region on Temporal Cloud
	FailoverNamespace(ctx context.Context, in *FailoverNamespaceRequest, opts ...grpc.CallOption) (*FailoverNamespaceResponse, error)
}

type namespaceServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewNamespaceServiceClient(cc grpc.ClientConnInterface) NamespaceServiceClient {
	return &namespaceServiceClient{cc}
}

func (c *namespaceServiceClient) CreateNamespace(ctx context.Context, in *CreateNamespaceRequest, opts ...grpc.CallOption) (*CreateNamespaceResponse, error) {
	out := new(CreateNamespaceResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/CreateNamespace", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) ListNamespaces(ctx context.Context, in *ListNamespacesRequest, opts ...grpc.CallOption) (*ListNamespacesResponse, error) {
	out := new(ListNamespacesResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/ListNamespaces", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) GetNamespaces(ctx context.Context, in *GetNamespacesRequest, opts ...grpc.CallOption) (*GetNamespacesResponse, error) {
	out := new(GetNamespacesResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/GetNamespaces", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) GetNamespace(ctx context.Context, in *GetNamespaceRequest, opts ...grpc.CallOption) (*GetNamespaceResponse, error) {
	out := new(GetNamespaceResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/GetNamespace", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) UpdateNamespace(ctx context.Context, in *UpdateNamespaceRequest, opts ...grpc.CallOption) (*UpdateNamespaceResponse, error) {
	out := new(UpdateNamespaceResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/UpdateNamespace", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) RenameCustomSearchAttribute(ctx context.Context, in *RenameCustomSearchAttributeRequest, opts ...grpc.CallOption) (*RenameCustomSearchAttributeResponse, error) {
	out := new(RenameCustomSearchAttributeResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/RenameCustomSearchAttribute", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) DeleteNamespace(ctx context.Context, in *DeleteNamespaceRequest, opts ...grpc.CallOption) (*DeleteNamespaceResponse, error) {
	out := new(DeleteNamespaceResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/DeleteNamespace", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) CreateExportSink(ctx context.Context, in *CreateExportSinkRequest, opts ...grpc.CallOption) (*CreateExportSinkResponse, error) {
	out := new(CreateExportSinkResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/CreateExportSink", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) GetExportSink(ctx context.Context, in *GetExportSinkRequest, opts ...grpc.CallOption) (*GetExportSinkResponse, error) {
	out := new(GetExportSinkResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/GetExportSink", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) DeleteExportSink(ctx context.Context, in *DeleteExportSinkRequest, opts ...grpc.CallOption) (*DeleteExportSinkResponse, error) {
	out := new(DeleteExportSinkResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/DeleteExportSink", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) UpdateExportSink(ctx context.Context, in *UpdateExportSinkRequest, opts ...grpc.CallOption) (*UpdateExportSinkResponse, error) {
	out := new(UpdateExportSinkResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/UpdateExportSink", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) ListExportSinks(ctx context.Context, in *ListExportSinksRequest, opts ...grpc.CallOption) (*ListExportSinksResponse, error) {
	out := new(ListExportSinksResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/ListExportSinks", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) ValidateExportSink(ctx context.Context, in *ValidateExportSinkRequest, opts ...grpc.CallOption) (*ValidateExportSinkResponse, error) {
	out := new(ValidateExportSinkResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/ValidateExportSink", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) GetExportSinks(ctx context.Context, in *GetExportSinksRequest, opts ...grpc.CallOption) (*GetExportSinksResponse, error) {
	out := new(GetExportSinksResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/GetExportSinks", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *namespaceServiceClient) FailoverNamespace(ctx context.Context, in *FailoverNamespaceRequest, opts ...grpc.CallOption) (*FailoverNamespaceResponse, error) {
	out := new(FailoverNamespaceResponse)
	err := c.cc.Invoke(ctx, "/api.namespaceservice.v1.NamespaceService/FailoverNamespace", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NamespaceServiceServer is the server API for NamespaceService service.
type NamespaceServiceServer interface {
	// CreateNamespace creates a new namespace on Temporal cloud.
	CreateNamespace(context.Context, *CreateNamespaceRequest) (*CreateNamespaceResponse, error)
	// ListNamespaces lists the names of all known namespaces on Temporal cloud.
	ListNamespaces(context.Context, *ListNamespacesRequest) (*ListNamespacesResponse, error)
	// GetNamespaces lists all known namespaces on temporal cloud.
	GetNamespaces(context.Context, *GetNamespacesRequest) (*GetNamespacesResponse, error)
	// GetNamespace describes the namespace in detail.
	GetNamespace(context.Context, *GetNamespaceRequest) (*GetNamespaceResponse, error)
	// UpdateNamespace updates an existing namespace on Temporal cloud.
	UpdateNamespace(context.Context, *UpdateNamespaceRequest) (*UpdateNamespaceResponse, error)
	// RenameCustomSearchAttribute renames an existing custom search attribute for a given namespace on Temporal cloud.
	RenameCustomSearchAttribute(context.Context, *RenameCustomSearchAttributeRequest) (*RenameCustomSearchAttributeResponse, error)
	// DeleteNamespace deletes an existing namespace on Temporal cloud.
	DeleteNamespace(context.Context, *DeleteNamespaceRequest) (*DeleteNamespaceResponse, error)
	// CreateExportSink creates a new sink under the specified namespace on Temporal cloud
	CreateExportSink(context.Context, *CreateExportSinkRequest) (*CreateExportSinkResponse, error)
	// GetExportSink gets the specified sink under the specified namespace on Temporal cloud
	GetExportSink(context.Context, *GetExportSinkRequest) (*GetExportSinkResponse, error)
	// DeleteExportSink deletes the specified sink under the specified namespace on Temporal cloud
	DeleteExportSink(context.Context, *DeleteExportSinkRequest) (*DeleteExportSinkResponse, error)
	// UpdateExportSink updates the specified sink under the specified namespace on Temporal Cloud
	UpdateExportSink(context.Context, *UpdateExportSinkRequest) (*UpdateExportSinkResponse, error)
	// ListExportSinks lists the export sinks under the specified namespace on Temporal Cloud
	ListExportSinks(context.Context, *ListExportSinksRequest) (*ListExportSinksResponse, error)
	// ValidateExportSink that could write test file to sink on Temporal Cloud
	ValidateExportSink(context.Context, *ValidateExportSinkRequest) (*ValidateExportSinkResponse, error)
	// GetExportSinks retrieves the export sinks under the specified namespace on Temporal Cloud
	GetExportSinks(context.Context, *GetExportSinksRequest) (*GetExportSinksResponse, error)
	// FailoverNamespace failovers the namespace from the source_region to the target_region on Temporal Cloud
	FailoverNamespace(context.Context, *FailoverNamespaceRequest) (*FailoverNamespaceResponse, error)
}

// UnimplementedNamespaceServiceServer can be embedded to have forward compatible implementations.
type UnimplementedNamespaceServiceServer struct {
}

func (*UnimplementedNamespaceServiceServer) CreateNamespace(ctx context.Context, req *CreateNamespaceRequest) (*CreateNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateNamespace not implemented")
}
func (*UnimplementedNamespaceServiceServer) ListNamespaces(ctx context.Context, req *ListNamespacesRequest) (*ListNamespacesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListNamespaces not implemented")
}
func (*UnimplementedNamespaceServiceServer) GetNamespaces(ctx context.Context, req *GetNamespacesRequest) (*GetNamespacesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNamespaces not implemented")
}
func (*UnimplementedNamespaceServiceServer) GetNamespace(ctx context.Context, req *GetNamespaceRequest) (*GetNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNamespace not implemented")
}
func (*UnimplementedNamespaceServiceServer) UpdateNamespace(ctx context.Context, req *UpdateNamespaceRequest) (*UpdateNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateNamespace not implemented")
}
func (*UnimplementedNamespaceServiceServer) RenameCustomSearchAttribute(ctx context.Context, req *RenameCustomSearchAttributeRequest) (*RenameCustomSearchAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RenameCustomSearchAttribute not implemented")
}
func (*UnimplementedNamespaceServiceServer) DeleteNamespace(ctx context.Context, req *DeleteNamespaceRequest) (*DeleteNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteNamespace not implemented")
}
func (*UnimplementedNamespaceServiceServer) CreateExportSink(ctx context.Context, req *CreateExportSinkRequest) (*CreateExportSinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateExportSink not implemented")
}
func (*UnimplementedNamespaceServiceServer) GetExportSink(ctx context.Context, req *GetExportSinkRequest) (*GetExportSinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetExportSink not implemented")
}
func (*UnimplementedNamespaceServiceServer) DeleteExportSink(ctx context.Context, req *DeleteExportSinkRequest) (*DeleteExportSinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteExportSink not implemented")
}
func (*UnimplementedNamespaceServiceServer) UpdateExportSink(ctx context.Context, req *UpdateExportSinkRequest) (*UpdateExportSinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateExportSink not implemented")
}
func (*UnimplementedNamespaceServiceServer) ListExportSinks(ctx context.Context, req *ListExportSinksRequest) (*ListExportSinksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListExportSinks not implemented")
}
func (*UnimplementedNamespaceServiceServer) ValidateExportSink(ctx context.Context, req *ValidateExportSinkRequest) (*ValidateExportSinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateExportSink not implemented")
}
func (*UnimplementedNamespaceServiceServer) GetExportSinks(ctx context.Context, req *GetExportSinksRequest) (*GetExportSinksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetExportSinks not implemented")
}
func (*UnimplementedNamespaceServiceServer) FailoverNamespace(ctx context.Context, req *FailoverNamespaceRequest) (*FailoverNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FailoverNamespace not implemented")
}

func RegisterNamespaceServiceServer(s *grpc.Server, srv NamespaceServiceServer) {
	s.RegisterService(&_NamespaceService_serviceDesc, srv)
}

func _NamespaceService_CreateNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).CreateNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/CreateNamespace",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).CreateNamespace(ctx, req.(*CreateNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_ListNamespaces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListNamespacesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).ListNamespaces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/ListNamespaces",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).ListNamespaces(ctx, req.(*ListNamespacesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_GetNamespaces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetNamespacesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).GetNamespaces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/GetNamespaces",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).GetNamespaces(ctx, req.(*GetNamespacesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_GetNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).GetNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/GetNamespace",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).GetNamespace(ctx, req.(*GetNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_UpdateNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).UpdateNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/UpdateNamespace",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).UpdateNamespace(ctx, req.(*UpdateNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_RenameCustomSearchAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RenameCustomSearchAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).RenameCustomSearchAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/RenameCustomSearchAttribute",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).RenameCustomSearchAttribute(ctx, req.(*RenameCustomSearchAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_DeleteNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).DeleteNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/DeleteNamespace",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).DeleteNamespace(ctx, req.(*DeleteNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_CreateExportSink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateExportSinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).CreateExportSink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/CreateExportSink",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).CreateExportSink(ctx, req.(*CreateExportSinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_GetExportSink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetExportSinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).GetExportSink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/GetExportSink",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).GetExportSink(ctx, req.(*GetExportSinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_DeleteExportSink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteExportSinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).DeleteExportSink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/DeleteExportSink",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).DeleteExportSink(ctx, req.(*DeleteExportSinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_UpdateExportSink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateExportSinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).UpdateExportSink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/UpdateExportSink",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).UpdateExportSink(ctx, req.(*UpdateExportSinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_ListExportSinks_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListExportSinksRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).ListExportSinks(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/ListExportSinks",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).ListExportSinks(ctx, req.(*ListExportSinksRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_ValidateExportSink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateExportSinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).ValidateExportSink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/ValidateExportSink",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).ValidateExportSink(ctx, req.(*ValidateExportSinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_GetExportSinks_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetExportSinksRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).GetExportSinks(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/GetExportSinks",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).GetExportSinks(ctx, req.(*GetExportSinksRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NamespaceService_FailoverNamespace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FailoverNamespaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NamespaceServiceServer).FailoverNamespace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.namespaceservice.v1.NamespaceService/FailoverNamespace",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NamespaceServiceServer).FailoverNamespace(ctx, req.(*FailoverNamespaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _NamespaceService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.namespaceservice.v1.NamespaceService",
	HandlerType: (*NamespaceServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateNamespace",
			Handler:    _NamespaceService_CreateNamespace_Handler,
		},
		{
			MethodName: "ListNamespaces",
			Handler:    _NamespaceService_ListNamespaces_Handler,
		},
		{
			MethodName: "GetNamespaces",
			Handler:    _NamespaceService_GetNamespaces_Handler,
		},
		{
			MethodName: "GetNamespace",
			Handler:    _NamespaceService_GetNamespace_Handler,
		},
		{
			MethodName: "UpdateNamespace",
			Handler:    _NamespaceService_UpdateNamespace_Handler,
		},
		{
			MethodName: "RenameCustomSearchAttribute",
			Handler:    _NamespaceService_RenameCustomSearchAttribute_Handler,
		},
		{
			MethodName: "DeleteNamespace",
			Handler:    _NamespaceService_DeleteNamespace_Handler,
		},
		{
			MethodName: "CreateExportSink",
			Handler:    _NamespaceService_CreateExportSink_Handler,
		},
		{
			MethodName: "GetExportSink",
			Handler:    _NamespaceService_GetExportSink_Handler,
		},
		{
			MethodName: "DeleteExportSink",
			Handler:    _NamespaceService_DeleteExportSink_Handler,
		},
		{
			MethodName: "UpdateExportSink",
			Handler:    _NamespaceService_UpdateExportSink_Handler,
		},
		{
			MethodName: "ListExportSinks",
			Handler:    _NamespaceService_ListExportSinks_Handler,
		},
		{
			MethodName: "ValidateExportSink",
			Handler:    _NamespaceService_ValidateExportSink_Handler,
		},
		{
			MethodName: "GetExportSinks",
			Handler:    _NamespaceService_GetExportSinks_Handler,
		},
		{
			MethodName: "FailoverNamespace",
			Handler:    _NamespaceService_FailoverNamespace_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/namespaceservice/v1/service.proto",
}
