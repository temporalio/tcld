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
	// 471 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x95, 0xbf, 0xae, 0xd3, 0x30,
	0x14, 0x87, 0xe3, 0x85, 0xc1, 0xe2, 0x72, 0x2f, 0x5e, 0x90, 0x2e, 0x92, 0x07, 0x24, 0x36, 0xae,
	0x43, 0x2f, 0x6c, 0x97, 0x05, 0xca, 0x9f, 0x05, 0x31, 0xb4, 0x62, 0x61, 0x41, 0x69, 0x7a, 0x24,
	0x02, 0x49, 0x63, 0x6c, 0x27, 0x02, 0x89, 0x81, 0x47, 0x60, 0xe6, 0x09, 0x78, 0x07, 0x5e, 0x80,
	0xb1, 0x63, 0x47, 0x9a, 0x2e, 0x8c, 0x7d, 0x04, 0x54, 0x52, 0xbb, 0x8e, 0xa3, 0x24, 0x2e, 0x5b,
	0x55, 0x7f, 0x3f, 0x7f, 0xf1, 0xf1, 0xc9, 0x09, 0xbe, 0x1b, 0xf1, 0x24, 0x5c, 0x44, 0x19, 0x48,
	0x1e, 0xc5, 0x20, 0x41, 0x94, 0x49, 0x0c, 0x61, 0x39, 0x0a, 0xf7, 0x3f, 0x19, 0x17, 0xb9, 0xca,
	0xc9, 0xad, 0x88, 0x27, 0xcc, 0xc5, 0x58, 0x39, 0x3a, 0x67, 0x5d, 0x79, 0x01, 0x1f, 0x0b, 0x90,
	0xea, 0xad, 0x00, 0xc9, 0xf3, 0x85, 0xdc, 0x6f, 0x74, 0xf9, 0xf3, 0x04, 0x9f, 0xbd, 0xd2, 0xf8,
	0xb4, 0xc6, 0x49, 0x89, 0x4f, 0xc7, 0x02, 0x22, 0x05, 0x66, 0x85, 0x84, 0xac, 0xc3, 0xc8, 0x1c,
	0x72, 0x52, 0x7b, 0xce, 0xef, 0xfb, 0x07, 0xea, 0x07, 0xba, 0x13, 0x10, 0x89, 0x6f, 0xbc, 0x4c,
	0xa4, 0x32, 0x4b, 0x92, 0xb0, 0xce, 0x5d, 0x9a, 0xa0, 0xb6, 0x86, 0xde, 0xbc, 0x91, 0x72, 0x7c,
	0xf2, 0x02, 0x6c, 0xe7, 0x45, 0xe7, 0x1e, 0x0d, 0x4e, 0x2b, 0x99, 0x2f, 0x6e, 0x8c, 0x19, 0xbe,
	0x6e, 0x2f, 0x91, 0x7b, 0x5e, 0x3b, 0x68, 0xdf, 0x85, 0x27, 0x6d, 0x74, 0x25, 0x3e, 0x7d, 0xcd,
	0xe7, 0x9e, 0xb7, 0xe9, 0x90, 0xc3, 0xb7, 0xd9, 0x0a, 0x18, 0xef, 0x77, 0x84, 0x6f, 0x4f, 0x60,
	0x97, 0x19, 0x17, 0x52, 0xe5, 0xd9, 0x14, 0x22, 0x11, 0xbf, 0x7b, 0xac, 0x94, 0x48, 0x66, 0x85,
	0x02, 0x72, 0xd5, 0xb9, 0x67, 0x4f, 0x4a, 0x3f, 0xd0, 0xa3, 0xff, 0x0b, 0xdb, 0x45, 0x79, 0x0a,
	0x29, 0xf8, 0x15, 0xc5, 0x21, 0x87, 0x8b, 0xd2, 0x0a, 0x18, 0xef, 0x67, 0x7c, 0x56, 0xf7, 0xff,
	0xb3, 0x4f, 0x3c, 0x17, 0x6a, 0x9a, 0x2c, 0x3e, 0x90, 0xa1, 0x57, 0xe5, 0x80, 0x6a, 0xf3, 0xe8,
	0x88, 0x84, 0xd3, 0xe8, 0x96, 0xb7, 0xb7, 0x93, 0xda, 0x52, 0xe6, 0x8b, 0xdb, 0x87, 0xad, 0x2b,
	0xe1, 0x75, 0x58, 0x17, 0x1d, 0x3e, 0x6c, 0x3b, 0x61, 0xab, 0xeb, 0xce, 0xf4, 0x52, 0xbb, 0xe8,
	0xb0, 0xba, 0x9d, 0xb0, 0x5b, 0x6b, 0x37, 0x6c, 0x0e, 0x6b, 0x92, 0xf4, 0x8f, 0x25, 0x8b, 0x1c,
	0x6e, 0xad, 0x56, 0xc0, 0x9e, 0x9e, 0x8d, 0x8b, 0xe8, 0x9b, 0x9e, 0x4d, 0x70, 0x78, 0x7a, 0xba,
	0xbc, 0x91, 0x7e, 0xc1, 0x37, 0x9f, 0x47, 0x49, 0x9a, 0x97, 0x20, 0x0e, 0x6f, 0x52, 0x77, 0xd9,
	0x5a, 0xac, 0x56, 0x5f, 0x1e, 0x13, 0xd1, 0xf6, 0x27, 0xef, 0x97, 0x6b, 0x1a, 0xac, 0xd6, 0x34,
	0xd8, 0xae, 0x29, 0xfa, 0x5a, 0x51, 0xf4, 0xa3, 0xa2, 0xe8, 0x57, 0x45, 0xd1, 0xb2, 0xa2, 0xe8,
	0x77, 0x45, 0xd1, 0x9f, 0x8a, 0x06, 0xdb, 0x8a, 0xa2, 0x6f, 0x1b, 0x1a, 0x2c, 0x37, 0x34, 0x58,
	0x6d, 0x68, 0xf0, 0xe6, 0xa1, 0xca, 0xb8, 0x48, 0x59, 0x9c, 0xe6, 0xc5, 0x3c, 0xec, 0xf8, 0x5e,
	0x5e, 0xb9, 0xff, 0xcd, 0xae, 0xfd, 0xfb, 0x60, 0x3e, 0xf8, 0x1b, 0x00, 0x00, 0xff, 0xff, 0x3f,
	0x9f, 0x8e, 0x77, 0xa2, 0x07, 0x00, 0x00,
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
