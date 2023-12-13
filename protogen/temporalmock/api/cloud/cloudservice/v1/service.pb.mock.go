// Code generated by MockGen. DO NOT EDIT.
// Source: temporal/api/cloud/cloudservice/v1/service.pb.go

// Package temporalmock is a generated GoMock package.
package temporalmock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	cloudservice "github.com/temporalio/tcld/protogen/temporal/api/cloud/cloudservice/v1"
	grpc "google.golang.org/grpc"
)

// MockCloudServiceClient is a mock of CloudServiceClient interface.
type MockCloudServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockCloudServiceClientMockRecorder
}

// MockCloudServiceClientMockRecorder is the mock recorder for MockCloudServiceClient.
type MockCloudServiceClientMockRecorder struct {
	mock *MockCloudServiceClient
}

// NewMockCloudServiceClient creates a new mock instance.
func NewMockCloudServiceClient(ctrl *gomock.Controller) *MockCloudServiceClient {
	mock := &MockCloudServiceClient{ctrl: ctrl}
	mock.recorder = &MockCloudServiceClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCloudServiceClient) EXPECT() *MockCloudServiceClientMockRecorder {
	return m.recorder
}

// CreateNamespace mocks base method.
func (m *MockCloudServiceClient) CreateNamespace(ctx context.Context, in *cloudservice.CreateNamespaceRequest, opts ...grpc.CallOption) (*cloudservice.CreateNamespaceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateNamespace", varargs...)
	ret0, _ := ret[0].(*cloudservice.CreateNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateNamespace indicates an expected call of CreateNamespace.
func (mr *MockCloudServiceClientMockRecorder) CreateNamespace(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateNamespace", reflect.TypeOf((*MockCloudServiceClient)(nil).CreateNamespace), varargs...)
}

// CreateUser mocks base method.
func (m *MockCloudServiceClient) CreateUser(ctx context.Context, in *cloudservice.CreateUserRequest, opts ...grpc.CallOption) (*cloudservice.CreateUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateUser", varargs...)
	ret0, _ := ret[0].(*cloudservice.CreateUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockCloudServiceClientMockRecorder) CreateUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockCloudServiceClient)(nil).CreateUser), varargs...)
}

// DeleteNamespace mocks base method.
func (m *MockCloudServiceClient) DeleteNamespace(ctx context.Context, in *cloudservice.DeleteNamespaceRequest, opts ...grpc.CallOption) (*cloudservice.DeleteNamespaceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteNamespace", varargs...)
	ret0, _ := ret[0].(*cloudservice.DeleteNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteNamespace indicates an expected call of DeleteNamespace.
func (mr *MockCloudServiceClientMockRecorder) DeleteNamespace(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteNamespace", reflect.TypeOf((*MockCloudServiceClient)(nil).DeleteNamespace), varargs...)
}

// DeleteUser mocks base method.
func (m *MockCloudServiceClient) DeleteUser(ctx context.Context, in *cloudservice.DeleteUserRequest, opts ...grpc.CallOption) (*cloudservice.DeleteUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteUser", varargs...)
	ret0, _ := ret[0].(*cloudservice.DeleteUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockCloudServiceClientMockRecorder) DeleteUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockCloudServiceClient)(nil).DeleteUser), varargs...)
}

// GetAsyncOperation mocks base method.
func (m *MockCloudServiceClient) GetAsyncOperation(ctx context.Context, in *cloudservice.GetAsyncOperationRequest, opts ...grpc.CallOption) (*cloudservice.GetAsyncOperationResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetAsyncOperation", varargs...)
	ret0, _ := ret[0].(*cloudservice.GetAsyncOperationResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAsyncOperation indicates an expected call of GetAsyncOperation.
func (mr *MockCloudServiceClientMockRecorder) GetAsyncOperation(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAsyncOperation", reflect.TypeOf((*MockCloudServiceClient)(nil).GetAsyncOperation), varargs...)
}

// GetNamespace mocks base method.
func (m *MockCloudServiceClient) GetNamespace(ctx context.Context, in *cloudservice.GetNamespaceRequest, opts ...grpc.CallOption) (*cloudservice.GetNamespaceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetNamespace", varargs...)
	ret0, _ := ret[0].(*cloudservice.GetNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNamespace indicates an expected call of GetNamespace.
func (mr *MockCloudServiceClientMockRecorder) GetNamespace(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespace", reflect.TypeOf((*MockCloudServiceClient)(nil).GetNamespace), varargs...)
}

// GetNamespaces mocks base method.
func (m *MockCloudServiceClient) GetNamespaces(ctx context.Context, in *cloudservice.GetNamespacesRequest, opts ...grpc.CallOption) (*cloudservice.GetNamespacesResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetNamespaces", varargs...)
	ret0, _ := ret[0].(*cloudservice.GetNamespacesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNamespaces indicates an expected call of GetNamespaces.
func (mr *MockCloudServiceClientMockRecorder) GetNamespaces(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespaces", reflect.TypeOf((*MockCloudServiceClient)(nil).GetNamespaces), varargs...)
}

// GetRegion mocks base method.
func (m *MockCloudServiceClient) GetRegion(ctx context.Context, in *cloudservice.GetRegionRequest, opts ...grpc.CallOption) (*cloudservice.GetRegionResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRegion", varargs...)
	ret0, _ := ret[0].(*cloudservice.GetRegionResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRegion indicates an expected call of GetRegion.
func (mr *MockCloudServiceClientMockRecorder) GetRegion(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRegion", reflect.TypeOf((*MockCloudServiceClient)(nil).GetRegion), varargs...)
}

// GetRegions mocks base method.
func (m *MockCloudServiceClient) GetRegions(ctx context.Context, in *cloudservice.GetRegionsRequest, opts ...grpc.CallOption) (*cloudservice.GetRegionsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRegions", varargs...)
	ret0, _ := ret[0].(*cloudservice.GetRegionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRegions indicates an expected call of GetRegions.
func (mr *MockCloudServiceClientMockRecorder) GetRegions(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRegions", reflect.TypeOf((*MockCloudServiceClient)(nil).GetRegions), varargs...)
}

// GetUser mocks base method.
func (m *MockCloudServiceClient) GetUser(ctx context.Context, in *cloudservice.GetUserRequest, opts ...grpc.CallOption) (*cloudservice.GetUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUser", varargs...)
	ret0, _ := ret[0].(*cloudservice.GetUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *MockCloudServiceClientMockRecorder) GetUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*MockCloudServiceClient)(nil).GetUser), varargs...)
}

// GetUsers mocks base method.
func (m *MockCloudServiceClient) GetUsers(ctx context.Context, in *cloudservice.GetUsersRequest, opts ...grpc.CallOption) (*cloudservice.GetUsersResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUsers", varargs...)
	ret0, _ := ret[0].(*cloudservice.GetUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *MockCloudServiceClientMockRecorder) GetUsers(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*MockCloudServiceClient)(nil).GetUsers), varargs...)
}

// RenameCustomSearchAttribute mocks base method.
func (m *MockCloudServiceClient) RenameCustomSearchAttribute(ctx context.Context, in *cloudservice.RenameCustomSearchAttributeRequest, opts ...grpc.CallOption) (*cloudservice.RenameCustomSearchAttributeResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RenameCustomSearchAttribute", varargs...)
	ret0, _ := ret[0].(*cloudservice.RenameCustomSearchAttributeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RenameCustomSearchAttribute indicates an expected call of RenameCustomSearchAttribute.
func (mr *MockCloudServiceClientMockRecorder) RenameCustomSearchAttribute(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RenameCustomSearchAttribute", reflect.TypeOf((*MockCloudServiceClient)(nil).RenameCustomSearchAttribute), varargs...)
}

// SetUserNamespaceAccess mocks base method.
func (m *MockCloudServiceClient) SetUserNamespaceAccess(ctx context.Context, in *cloudservice.SetUserNamespaceAccessRequest, opts ...grpc.CallOption) (*cloudservice.SetUserNamespaceAccessResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SetUserNamespaceAccess", varargs...)
	ret0, _ := ret[0].(*cloudservice.SetUserNamespaceAccessResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SetUserNamespaceAccess indicates an expected call of SetUserNamespaceAccess.
func (mr *MockCloudServiceClientMockRecorder) SetUserNamespaceAccess(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUserNamespaceAccess", reflect.TypeOf((*MockCloudServiceClient)(nil).SetUserNamespaceAccess), varargs...)
}

// UpdateNamespace mocks base method.
func (m *MockCloudServiceClient) UpdateNamespace(ctx context.Context, in *cloudservice.UpdateNamespaceRequest, opts ...grpc.CallOption) (*cloudservice.UpdateNamespaceResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateNamespace", varargs...)
	ret0, _ := ret[0].(*cloudservice.UpdateNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateNamespace indicates an expected call of UpdateNamespace.
func (mr *MockCloudServiceClientMockRecorder) UpdateNamespace(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateNamespace", reflect.TypeOf((*MockCloudServiceClient)(nil).UpdateNamespace), varargs...)
}

// UpdateUser mocks base method.
func (m *MockCloudServiceClient) UpdateUser(ctx context.Context, in *cloudservice.UpdateUserRequest, opts ...grpc.CallOption) (*cloudservice.UpdateUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateUser", varargs...)
	ret0, _ := ret[0].(*cloudservice.UpdateUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockCloudServiceClientMockRecorder) UpdateUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockCloudServiceClient)(nil).UpdateUser), varargs...)
}

// MockCloudServiceServer is a mock of CloudServiceServer interface.
type MockCloudServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockCloudServiceServerMockRecorder
}

// MockCloudServiceServerMockRecorder is the mock recorder for MockCloudServiceServer.
type MockCloudServiceServerMockRecorder struct {
	mock *MockCloudServiceServer
}

// NewMockCloudServiceServer creates a new mock instance.
func NewMockCloudServiceServer(ctrl *gomock.Controller) *MockCloudServiceServer {
	mock := &MockCloudServiceServer{ctrl: ctrl}
	mock.recorder = &MockCloudServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCloudServiceServer) EXPECT() *MockCloudServiceServerMockRecorder {
	return m.recorder
}

// CreateNamespace mocks base method.
func (m *MockCloudServiceServer) CreateNamespace(arg0 context.Context, arg1 *cloudservice.CreateNamespaceRequest) (*cloudservice.CreateNamespaceResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateNamespace", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.CreateNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateNamespace indicates an expected call of CreateNamespace.
func (mr *MockCloudServiceServerMockRecorder) CreateNamespace(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateNamespace", reflect.TypeOf((*MockCloudServiceServer)(nil).CreateNamespace), arg0, arg1)
}

// CreateUser mocks base method.
func (m *MockCloudServiceServer) CreateUser(arg0 context.Context, arg1 *cloudservice.CreateUserRequest) (*cloudservice.CreateUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.CreateUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockCloudServiceServerMockRecorder) CreateUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockCloudServiceServer)(nil).CreateUser), arg0, arg1)
}

// DeleteNamespace mocks base method.
func (m *MockCloudServiceServer) DeleteNamespace(arg0 context.Context, arg1 *cloudservice.DeleteNamespaceRequest) (*cloudservice.DeleteNamespaceResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteNamespace", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.DeleteNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteNamespace indicates an expected call of DeleteNamespace.
func (mr *MockCloudServiceServerMockRecorder) DeleteNamespace(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteNamespace", reflect.TypeOf((*MockCloudServiceServer)(nil).DeleteNamespace), arg0, arg1)
}

// DeleteUser mocks base method.
func (m *MockCloudServiceServer) DeleteUser(arg0 context.Context, arg1 *cloudservice.DeleteUserRequest) (*cloudservice.DeleteUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.DeleteUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockCloudServiceServerMockRecorder) DeleteUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockCloudServiceServer)(nil).DeleteUser), arg0, arg1)
}

// GetAsyncOperation mocks base method.
func (m *MockCloudServiceServer) GetAsyncOperation(arg0 context.Context, arg1 *cloudservice.GetAsyncOperationRequest) (*cloudservice.GetAsyncOperationResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAsyncOperation", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.GetAsyncOperationResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAsyncOperation indicates an expected call of GetAsyncOperation.
func (mr *MockCloudServiceServerMockRecorder) GetAsyncOperation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAsyncOperation", reflect.TypeOf((*MockCloudServiceServer)(nil).GetAsyncOperation), arg0, arg1)
}

// GetNamespace mocks base method.
func (m *MockCloudServiceServer) GetNamespace(arg0 context.Context, arg1 *cloudservice.GetNamespaceRequest) (*cloudservice.GetNamespaceResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNamespace", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.GetNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNamespace indicates an expected call of GetNamespace.
func (mr *MockCloudServiceServerMockRecorder) GetNamespace(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespace", reflect.TypeOf((*MockCloudServiceServer)(nil).GetNamespace), arg0, arg1)
}

// GetNamespaces mocks base method.
func (m *MockCloudServiceServer) GetNamespaces(arg0 context.Context, arg1 *cloudservice.GetNamespacesRequest) (*cloudservice.GetNamespacesResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNamespaces", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.GetNamespacesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNamespaces indicates an expected call of GetNamespaces.
func (mr *MockCloudServiceServerMockRecorder) GetNamespaces(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespaces", reflect.TypeOf((*MockCloudServiceServer)(nil).GetNamespaces), arg0, arg1)
}

// GetRegion mocks base method.
func (m *MockCloudServiceServer) GetRegion(arg0 context.Context, arg1 *cloudservice.GetRegionRequest) (*cloudservice.GetRegionResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRegion", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.GetRegionResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRegion indicates an expected call of GetRegion.
func (mr *MockCloudServiceServerMockRecorder) GetRegion(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRegion", reflect.TypeOf((*MockCloudServiceServer)(nil).GetRegion), arg0, arg1)
}

// GetRegions mocks base method.
func (m *MockCloudServiceServer) GetRegions(arg0 context.Context, arg1 *cloudservice.GetRegionsRequest) (*cloudservice.GetRegionsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRegions", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.GetRegionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRegions indicates an expected call of GetRegions.
func (mr *MockCloudServiceServerMockRecorder) GetRegions(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRegions", reflect.TypeOf((*MockCloudServiceServer)(nil).GetRegions), arg0, arg1)
}

// GetUser mocks base method.
func (m *MockCloudServiceServer) GetUser(arg0 context.Context, arg1 *cloudservice.GetUserRequest) (*cloudservice.GetUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.GetUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *MockCloudServiceServerMockRecorder) GetUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*MockCloudServiceServer)(nil).GetUser), arg0, arg1)
}

// GetUsers mocks base method.
func (m *MockCloudServiceServer) GetUsers(arg0 context.Context, arg1 *cloudservice.GetUsersRequest) (*cloudservice.GetUsersResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUsers", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.GetUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *MockCloudServiceServerMockRecorder) GetUsers(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*MockCloudServiceServer)(nil).GetUsers), arg0, arg1)
}

// RenameCustomSearchAttribute mocks base method.
func (m *MockCloudServiceServer) RenameCustomSearchAttribute(arg0 context.Context, arg1 *cloudservice.RenameCustomSearchAttributeRequest) (*cloudservice.RenameCustomSearchAttributeResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RenameCustomSearchAttribute", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.RenameCustomSearchAttributeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RenameCustomSearchAttribute indicates an expected call of RenameCustomSearchAttribute.
func (mr *MockCloudServiceServerMockRecorder) RenameCustomSearchAttribute(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RenameCustomSearchAttribute", reflect.TypeOf((*MockCloudServiceServer)(nil).RenameCustomSearchAttribute), arg0, arg1)
}

// SetUserNamespaceAccess mocks base method.
func (m *MockCloudServiceServer) SetUserNamespaceAccess(arg0 context.Context, arg1 *cloudservice.SetUserNamespaceAccessRequest) (*cloudservice.SetUserNamespaceAccessResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUserNamespaceAccess", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.SetUserNamespaceAccessResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SetUserNamespaceAccess indicates an expected call of SetUserNamespaceAccess.
func (mr *MockCloudServiceServerMockRecorder) SetUserNamespaceAccess(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUserNamespaceAccess", reflect.TypeOf((*MockCloudServiceServer)(nil).SetUserNamespaceAccess), arg0, arg1)
}

// UpdateNamespace mocks base method.
func (m *MockCloudServiceServer) UpdateNamespace(arg0 context.Context, arg1 *cloudservice.UpdateNamespaceRequest) (*cloudservice.UpdateNamespaceResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateNamespace", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.UpdateNamespaceResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateNamespace indicates an expected call of UpdateNamespace.
func (mr *MockCloudServiceServerMockRecorder) UpdateNamespace(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateNamespace", reflect.TypeOf((*MockCloudServiceServer)(nil).UpdateNamespace), arg0, arg1)
}

// UpdateUser mocks base method.
func (m *MockCloudServiceServer) UpdateUser(arg0 context.Context, arg1 *cloudservice.UpdateUserRequest) (*cloudservice.UpdateUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", arg0, arg1)
	ret0, _ := ret[0].(*cloudservice.UpdateUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockCloudServiceServerMockRecorder) UpdateUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockCloudServiceServer)(nil).UpdateUser), arg0, arg1)
}
