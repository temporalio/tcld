// Code generated by MockGen. DO NOT EDIT.
// Source: api/authservice/v1/service.pb.go

// Package apimock is a generated GoMock package.
package apimock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1 "github.com/temporalio/tcld/protogen/api/authservice/v1"
	grpc "google.golang.org/grpc"
)

// MockAuthServiceClient is a mock of AuthServiceClient interface.
type MockAuthServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockAuthServiceClientMockRecorder
}

// MockAuthServiceClientMockRecorder is the mock recorder for MockAuthServiceClient.
type MockAuthServiceClientMockRecorder struct {
	mock *MockAuthServiceClient
}

// NewMockAuthServiceClient creates a new mock instance.
func NewMockAuthServiceClient(ctrl *gomock.Controller) *MockAuthServiceClient {
	mock := &MockAuthServiceClient{ctrl: ctrl}
	mock.recorder = &MockAuthServiceClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthServiceClient) EXPECT() *MockAuthServiceClientMockRecorder {
	return m.recorder
}

// DeleteUser mocks base method.
func (m *MockAuthServiceClient) DeleteUser(ctx context.Context, in *v1.DeleteUserRequest, opts ...grpc.CallOption) (*v1.DeleteUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteUser", varargs...)
	ret0, _ := ret[0].(*v1.DeleteUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockAuthServiceClientMockRecorder) DeleteUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockAuthServiceClient)(nil).DeleteUser), varargs...)
}

// GetRoles mocks base method.
func (m *MockAuthServiceClient) GetRoles(ctx context.Context, in *v1.GetRolesRequest, opts ...grpc.CallOption) (*v1.GetRolesResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRoles", varargs...)
	ret0, _ := ret[0].(*v1.GetRolesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRoles indicates an expected call of GetRoles.
func (mr *MockAuthServiceClientMockRecorder) GetRoles(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRoles", reflect.TypeOf((*MockAuthServiceClient)(nil).GetRoles), varargs...)
}

// GetRolesByPermissions mocks base method.
func (m *MockAuthServiceClient) GetRolesByPermissions(ctx context.Context, in *v1.GetRolesByPermissionsRequest, opts ...grpc.CallOption) (*v1.GetRolesByPermissionsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRolesByPermissions", varargs...)
	ret0, _ := ret[0].(*v1.GetRolesByPermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRolesByPermissions indicates an expected call of GetRolesByPermissions.
func (mr *MockAuthServiceClientMockRecorder) GetRolesByPermissions(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRolesByPermissions", reflect.TypeOf((*MockAuthServiceClient)(nil).GetRolesByPermissions), varargs...)
}

// GetUser mocks base method.
func (m *MockAuthServiceClient) GetUser(ctx context.Context, in *v1.GetUserRequest, opts ...grpc.CallOption) (*v1.GetUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUser", varargs...)
	ret0, _ := ret[0].(*v1.GetUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *MockAuthServiceClientMockRecorder) GetUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*MockAuthServiceClient)(nil).GetUser), varargs...)
}

// GetUsers mocks base method.
func (m *MockAuthServiceClient) GetUsers(ctx context.Context, in *v1.GetUsersRequest, opts ...grpc.CallOption) (*v1.GetUsersResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUsers", varargs...)
	ret0, _ := ret[0].(*v1.GetUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *MockAuthServiceClientMockRecorder) GetUsers(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*MockAuthServiceClient)(nil).GetUsers), varargs...)
}

// InviteUsers mocks base method.
func (m *MockAuthServiceClient) InviteUsers(ctx context.Context, in *v1.InviteUsersRequest, opts ...grpc.CallOption) (*v1.InviteUsersResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "InviteUsers", varargs...)
	ret0, _ := ret[0].(*v1.InviteUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InviteUsers indicates an expected call of InviteUsers.
func (mr *MockAuthServiceClientMockRecorder) InviteUsers(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InviteUsers", reflect.TypeOf((*MockAuthServiceClient)(nil).InviteUsers), varargs...)
}

// ResendUserInvite mocks base method.
func (m *MockAuthServiceClient) ResendUserInvite(ctx context.Context, in *v1.ResendUserInviteRequest, opts ...grpc.CallOption) (*v1.ResendUserInviteResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ResendUserInvite", varargs...)
	ret0, _ := ret[0].(*v1.ResendUserInviteResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResendUserInvite indicates an expected call of ResendUserInvite.
func (mr *MockAuthServiceClientMockRecorder) ResendUserInvite(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResendUserInvite", reflect.TypeOf((*MockAuthServiceClient)(nil).ResendUserInvite), varargs...)
}

// UpdateUser mocks base method.
func (m *MockAuthServiceClient) UpdateUser(ctx context.Context, in *v1.UpdateUserRequest, opts ...grpc.CallOption) (*v1.UpdateUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateUser", varargs...)
	ret0, _ := ret[0].(*v1.UpdateUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockAuthServiceClientMockRecorder) UpdateUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockAuthServiceClient)(nil).UpdateUser), varargs...)
}

// UpdateUserNamespacePermissions mocks base method.
func (m *MockAuthServiceClient) UpdateUserNamespacePermissions(ctx context.Context, in *v1.UpdateUserNamespacePermissionsRequest, opts ...grpc.CallOption) (*v1.UpdateUserNamespacePermissionsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateUserNamespacePermissions", varargs...)
	ret0, _ := ret[0].(*v1.UpdateUserNamespacePermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUserNamespacePermissions indicates an expected call of UpdateUserNamespacePermissions.
func (mr *MockAuthServiceClientMockRecorder) UpdateUserNamespacePermissions(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserNamespacePermissions", reflect.TypeOf((*MockAuthServiceClient)(nil).UpdateUserNamespacePermissions), varargs...)
}

// MockAuthServiceServer is a mock of AuthServiceServer interface.
type MockAuthServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockAuthServiceServerMockRecorder
}

// MockAuthServiceServerMockRecorder is the mock recorder for MockAuthServiceServer.
type MockAuthServiceServerMockRecorder struct {
	mock *MockAuthServiceServer
}

// NewMockAuthServiceServer creates a new mock instance.
func NewMockAuthServiceServer(ctrl *gomock.Controller) *MockAuthServiceServer {
	mock := &MockAuthServiceServer{ctrl: ctrl}
	mock.recorder = &MockAuthServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthServiceServer) EXPECT() *MockAuthServiceServerMockRecorder {
	return m.recorder
}

// DeleteUser mocks base method.
func (m *MockAuthServiceServer) DeleteUser(arg0 context.Context, arg1 *v1.DeleteUserRequest) (*v1.DeleteUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", arg0, arg1)
	ret0, _ := ret[0].(*v1.DeleteUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockAuthServiceServerMockRecorder) DeleteUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockAuthServiceServer)(nil).DeleteUser), arg0, arg1)
}

// GetRoles mocks base method.
func (m *MockAuthServiceServer) GetRoles(arg0 context.Context, arg1 *v1.GetRolesRequest) (*v1.GetRolesResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRoles", arg0, arg1)
	ret0, _ := ret[0].(*v1.GetRolesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRoles indicates an expected call of GetRoles.
func (mr *MockAuthServiceServerMockRecorder) GetRoles(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRoles", reflect.TypeOf((*MockAuthServiceServer)(nil).GetRoles), arg0, arg1)
}

// GetRolesByPermissions mocks base method.
func (m *MockAuthServiceServer) GetRolesByPermissions(arg0 context.Context, arg1 *v1.GetRolesByPermissionsRequest) (*v1.GetRolesByPermissionsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRolesByPermissions", arg0, arg1)
	ret0, _ := ret[0].(*v1.GetRolesByPermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRolesByPermissions indicates an expected call of GetRolesByPermissions.
func (mr *MockAuthServiceServerMockRecorder) GetRolesByPermissions(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRolesByPermissions", reflect.TypeOf((*MockAuthServiceServer)(nil).GetRolesByPermissions), arg0, arg1)
}

// GetUser mocks base method.
func (m *MockAuthServiceServer) GetUser(arg0 context.Context, arg1 *v1.GetUserRequest) (*v1.GetUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", arg0, arg1)
	ret0, _ := ret[0].(*v1.GetUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *MockAuthServiceServerMockRecorder) GetUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*MockAuthServiceServer)(nil).GetUser), arg0, arg1)
}

// GetUsers mocks base method.
func (m *MockAuthServiceServer) GetUsers(arg0 context.Context, arg1 *v1.GetUsersRequest) (*v1.GetUsersResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUsers", arg0, arg1)
	ret0, _ := ret[0].(*v1.GetUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *MockAuthServiceServerMockRecorder) GetUsers(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*MockAuthServiceServer)(nil).GetUsers), arg0, arg1)
}

// InviteUsers mocks base method.
func (m *MockAuthServiceServer) InviteUsers(arg0 context.Context, arg1 *v1.InviteUsersRequest) (*v1.InviteUsersResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InviteUsers", arg0, arg1)
	ret0, _ := ret[0].(*v1.InviteUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InviteUsers indicates an expected call of InviteUsers.
func (mr *MockAuthServiceServerMockRecorder) InviteUsers(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InviteUsers", reflect.TypeOf((*MockAuthServiceServer)(nil).InviteUsers), arg0, arg1)
}

// ResendUserInvite mocks base method.
func (m *MockAuthServiceServer) ResendUserInvite(arg0 context.Context, arg1 *v1.ResendUserInviteRequest) (*v1.ResendUserInviteResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResendUserInvite", arg0, arg1)
	ret0, _ := ret[0].(*v1.ResendUserInviteResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResendUserInvite indicates an expected call of ResendUserInvite.
func (mr *MockAuthServiceServerMockRecorder) ResendUserInvite(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResendUserInvite", reflect.TypeOf((*MockAuthServiceServer)(nil).ResendUserInvite), arg0, arg1)
}

// UpdateUser mocks base method.
func (m *MockAuthServiceServer) UpdateUser(arg0 context.Context, arg1 *v1.UpdateUserRequest) (*v1.UpdateUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", arg0, arg1)
	ret0, _ := ret[0].(*v1.UpdateUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockAuthServiceServerMockRecorder) UpdateUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockAuthServiceServer)(nil).UpdateUser), arg0, arg1)
}

// UpdateUserNamespacePermissions mocks base method.
func (m *MockAuthServiceServer) UpdateUserNamespacePermissions(arg0 context.Context, arg1 *v1.UpdateUserNamespacePermissionsRequest) (*v1.UpdateUserNamespacePermissionsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserNamespacePermissions", arg0, arg1)
	ret0, _ := ret[0].(*v1.UpdateUserNamespacePermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUserNamespacePermissions indicates an expected call of UpdateUserNamespacePermissions.
func (mr *MockAuthServiceServerMockRecorder) UpdateUserNamespacePermissions(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserNamespacePermissions", reflect.TypeOf((*MockAuthServiceServer)(nil).UpdateUserNamespacePermissions), arg0, arg1)
}
