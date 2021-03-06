// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/namespaceservice/v1/service.proto

package namespaceservice

import (
	context "context"
	fmt "fmt"
	math "math"

	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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
	// 323 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0xb1, 0x4e, 0xeb, 0x30,
	0x14, 0x86, 0xed, 0xe1, 0xde, 0xc1, 0x42, 0x14, 0x79, 0x41, 0x2a, 0xd2, 0x19, 0x90, 0xd8, 0xc0,
	0xa6, 0xc0, 0x56, 0x16, 0xe8, 0xc0, 0x82, 0x18, 0x5a, 0xb1, 0xb0, 0x20, 0x37, 0x3d, 0x12, 0x41,
	0x4d, 0x63, 0x6c, 0x27, 0x33, 0x12, 0x2f, 0xc0, 0xcc, 0x13, 0xf0, 0x28, 0x8c, 0x1d, 0x3b, 0x52,
	0x77, 0x61, 0xec, 0x23, 0x20, 0x68, 0x13, 0x20, 0xc8, 0x10, 0xb1, 0x45, 0x39, 0xdf, 0xff, 0x7f,
	0x47, 0xd6, 0x61, 0x5b, 0x4a, 0xc7, 0x72, 0xa4, 0x12, 0xb4, 0x5a, 0x45, 0x68, 0xd1, 0xe4, 0x71,
	0x84, 0x32, 0x6f, 0xc9, 0xe5, 0xa7, 0xd0, 0x26, 0x75, 0x29, 0x5f, 0x57, 0x3a, 0x16, 0x55, 0x4c,
	0xe4, 0xad, 0xa6, 0x08, 0xe5, 0x0d, 0xde, 0x64, 0x68, 0xdd, 0xa5, 0x41, 0xab, 0xd3, 0x91, 0x5d,
	0x16, 0xed, 0xdd, 0xfd, 0x63, 0x6b, 0x67, 0x05, 0xde, 0x5b, 0xe0, 0x3c, 0x67, 0x8d, 0x8e, 0x41,
	0xe5, 0xb0, 0x9c, 0x70, 0x29, 0x02, 0x46, 0x51, 0x21, 0xbb, 0x0b, 0x4f, 0x73, 0xb7, 0x7e, 0x60,
	0xb1, 0xd0, 0x26, 0xe1, 0x96, 0xad, 0x9e, 0xc6, 0xd6, 0x95, 0x23, 0xcb, 0x45, 0xb0, 0xe5, 0x2b,
	0x58, 0x58, 0x65, 0x6d, 0xbe, 0x94, 0x26, 0x6c, 0xe5, 0x04, 0x3f, 0x46, 0x7c, 0x3b, 0x58, 0xf1,
	0x19, 0x2b, 0x84, 0x3b, 0x35, 0xe9, 0x52, 0x97, 0xb3, 0xc6, 0xb9, 0x1e, 0xd4, 0x7c, 0xdb, 0x0a,
	0xf9, 0xfb, 0xdb, 0x7e, 0x0b, 0x94, 0xde, 0x07, 0xca, 0x36, 0xba, 0xf8, 0x96, 0xe9, 0x64, 0xd6,
	0xa5, 0x49, 0x0f, 0x95, 0x89, 0xae, 0x8e, 0x9c, 0x33, 0x71, 0x3f, 0x73, 0xc8, 0xdb, 0xc1, 0xce,
	0x1f, 0x52, 0xc5, 0x42, 0x87, 0x7f, 0x0b, 0x17, 0xcb, 0x1d, 0x5f, 0x8f, 0xa7, 0x40, 0x26, 0x53,
	0x20, 0xf3, 0x29, 0xd0, 0x5b, 0x0f, 0xf4, 0xd1, 0x03, 0x7d, 0xf2, 0x40, 0xc7, 0x1e, 0xe8, 0xb3,
	0x07, 0xfa, 0xe2, 0x81, 0xcc, 0x3d, 0xd0, 0xfb, 0x19, 0x90, 0xf1, 0x0c, 0xc8, 0x64, 0x06, 0xe4,
	0xe2, 0xc0, 0x25, 0xda, 0x0c, 0x45, 0x34, 0x4c, 0xb3, 0x81, 0x0c, 0xdc, 0x7d, 0xbb, 0xfa, 0xaf,
	0xff, 0xff, 0xfd, 0xf0, 0xf7, 0x5f, 0x03, 0x00, 0x00, 0xff, 0xff, 0x8b, 0x66, 0x40, 0xb6, 0x6a,
	0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

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
	// GetNamespace describes the namespace in detail.
	GetNamespace(ctx context.Context, in *GetNamespaceRequest, opts ...grpc.CallOption) (*GetNamespaceResponse, error)
	// UpdateNamespace updates an existing namespace on Temporal cloud.
	UpdateNamespace(ctx context.Context, in *UpdateNamespaceRequest, opts ...grpc.CallOption) (*UpdateNamespaceResponse, error)
	// RenameCustomSearchAttribute renames an existing custom search attribute for a given namespace on Temporal cloud.
	RenameCustomSearchAttribute(ctx context.Context, in *RenameCustomSearchAttributeRequest, opts ...grpc.CallOption) (*RenameCustomSearchAttributeResponse, error)
}

type namespaceServiceClient struct {
	cc *grpc.ClientConn
}

func NewNamespaceServiceClient(cc *grpc.ClientConn) NamespaceServiceClient {
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

// NamespaceServiceServer is the server API for NamespaceService service.
type NamespaceServiceServer interface {
	// CreateNamespace creates a new namespace on Temporal cloud.
	CreateNamespace(context.Context, *CreateNamespaceRequest) (*CreateNamespaceResponse, error)
	// ListNamespaces lists the names of all known namespaces on Temporal cloud.
	ListNamespaces(context.Context, *ListNamespacesRequest) (*ListNamespacesResponse, error)
	// GetNamespace describes the namespace in detail.
	GetNamespace(context.Context, *GetNamespaceRequest) (*GetNamespaceResponse, error)
	// UpdateNamespace updates an existing namespace on Temporal cloud.
	UpdateNamespace(context.Context, *UpdateNamespaceRequest) (*UpdateNamespaceResponse, error)
	// RenameCustomSearchAttribute renames an existing custom search attribute for a given namespace on Temporal cloud.
	RenameCustomSearchAttribute(context.Context, *RenameCustomSearchAttributeRequest) (*RenameCustomSearchAttributeResponse, error)
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
func (*UnimplementedNamespaceServiceServer) GetNamespace(ctx context.Context, req *GetNamespaceRequest) (*GetNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNamespace not implemented")
}
func (*UnimplementedNamespaceServiceServer) UpdateNamespace(ctx context.Context, req *UpdateNamespaceRequest) (*UpdateNamespaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateNamespace not implemented")
}
func (*UnimplementedNamespaceServiceServer) RenameCustomSearchAttribute(ctx context.Context, req *RenameCustomSearchAttributeRequest) (*RenameCustomSearchAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RenameCustomSearchAttribute not implemented")
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
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/namespaceservice/v1/service.proto",
}
