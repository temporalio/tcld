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
	// 351 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x93, 0xb1, 0x4e, 0xeb, 0x30,
	0x14, 0x86, 0xed, 0xa5, 0x83, 0x75, 0x2f, 0x45, 0x5e, 0x90, 0x8a, 0x74, 0x06, 0x24, 0x36, 0xea,
	0x50, 0x60, 0x2b, 0x0b, 0x14, 0x89, 0x05, 0x31, 0xb4, 0x62, 0x61, 0x41, 0x69, 0x7a, 0x24, 0x82,
	0x9a, 0xc6, 0xd8, 0x4e, 0x66, 0x1e, 0x81, 0x99, 0x27, 0xe0, 0x51, 0x18, 0x3b, 0x76, 0xa4, 0xee,
	0xc2, 0x82, 0xd4, 0x47, 0x40, 0xd0, 0x26, 0x4a, 0x53, 0x85, 0x5a, 0x6c, 0x51, 0xce, 0xf7, 0xff,
	0x9f, 0x75, 0x2c, 0xb3, 0x7d, 0x5f, 0x86, 0xde, 0xc8, 0x8f, 0x50, 0x4b, 0x3f, 0x40, 0x8d, 0x2a,
	0x0d, 0x03, 0xf4, 0xd2, 0x96, 0xb7, 0xfc, 0x14, 0x52, 0xc5, 0x26, 0xe6, 0x3b, 0xbe, 0x0c, 0x45,
	0x19, 0x13, 0x69, 0xab, 0x21, 0xaa, 0xf2, 0x0a, 0x1f, 0x13, 0xd4, 0xe6, 0x4e, 0xa1, 0x96, 0xf1,
	0x48, 0x2f, 0x8b, 0x8e, 0x3e, 0x6b, 0x6c, 0xfb, 0x3a, 0xc3, 0x7b, 0x0b, 0x9c, 0xa7, 0xac, 0xde,
	0x51, 0xe8, 0x1b, 0xcc, 0x27, 0xdc, 0x13, 0x15, 0x46, 0x51, 0x22, 0xbb, 0x0b, 0x4f, 0xe3, 0xd0,
	0x3d, 0xb0, 0x38, 0xd0, 0x1e, 0xe1, 0x9a, 0x6d, 0x5d, 0x85, 0xda, 0xe4, 0x23, 0xcd, 0x45, 0x65,
	0xcb, 0x2a, 0x98, 0x59, 0x3d, 0x67, 0x3e, 0x97, 0x4a, 0xf6, 0xff, 0x12, 0x8b, 0xce, 0x66, 0x65,
	0xc7, 0x0a, 0x97, 0x29, 0x85, 0x2b, 0x9e, 0x1b, 0x23, 0xf6, 0xaf, 0x38, 0xe2, 0x07, 0x4e, 0x0d,
	0x99, 0xaf, 0xe9, 0x48, 0xe7, 0xba, 0x94, 0xd5, 0x6f, 0xe4, 0xc0, 0xf1, 0x36, 0x4b, 0xe4, 0xe6,
	0xdb, 0x5c, 0x0b, 0xe4, 0xde, 0x17, 0xca, 0x76, 0xbb, 0xf8, 0x9d, 0xe9, 0x24, 0xda, 0xc4, 0x51,
	0x0f, 0x7d, 0x15, 0xdc, 0x9f, 0x19, 0xa3, 0xc2, 0x7e, 0x62, 0x90, 0xb7, 0x2b, 0x3b, 0x7f, 0x49,
	0x65, 0x07, 0x3a, 0xfd, 0x5b, 0xb8, 0xb8, 0x94, 0x0b, 0x1c, 0xa2, 0xdb, 0x52, 0x4a, 0xe4, 0xe6,
	0xa5, 0xac, 0x05, 0x32, 0xef, 0xf9, 0xc3, 0x78, 0x0a, 0x64, 0x32, 0x05, 0x32, 0x9f, 0x02, 0x7d,
	0xb2, 0x40, 0x5f, 0x2d, 0xd0, 0x37, 0x0b, 0x74, 0x6c, 0x81, 0xbe, 0x5b, 0xa0, 0x1f, 0x16, 0xc8,
	0xdc, 0x02, 0x7d, 0x9e, 0x01, 0x19, 0xcf, 0x80, 0x4c, 0x66, 0x40, 0x6e, 0x4f, 0x4c, 0x24, 0xd5,
	0x50, 0x04, 0xc3, 0x38, 0x19, 0x78, 0x15, 0x2f, 0xbc, 0x5d, 0xfe, 0xd7, 0xaf, 0xfd, 0x3c, 0xf1,
	0xe3, 0xaf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x50, 0x0d, 0x48, 0xd1, 0x54, 0x04, 0x00, 0x00,
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
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/namespaceservice/v1/service.proto",
}