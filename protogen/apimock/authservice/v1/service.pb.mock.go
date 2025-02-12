// Code generated by MockGen. DO NOT EDIT.
// Source: api/authservice/v1/service.pb.go

// Package apimock is a generated GoMock package.
package apimock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	authservice "github.com/temporalio/saas-proto/protogen/api/authservice/v1"
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

// CreateAPIKey mocks base method.
func (m *MockAuthServiceClient) CreateAPIKey(ctx context.Context, in *authservice.CreateAPIKeyRequest, opts ...grpc.CallOption) (*authservice.CreateAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateAPIKey", varargs...)
	ret0, _ := ret[0].(*authservice.CreateAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAPIKey indicates an expected call of CreateAPIKey.
func (mr *MockAuthServiceClientMockRecorder) CreateAPIKey(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAPIKey", reflect.TypeOf((*MockAuthServiceClient)(nil).CreateAPIKey), varargs...)
}

// CreateServiceAccount mocks base method.
func (m *MockAuthServiceClient) CreateServiceAccount(ctx context.Context, in *authservice.CreateServiceAccountRequest, opts ...grpc.CallOption) (*authservice.CreateServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateServiceAccount", varargs...)
	ret0, _ := ret[0].(*authservice.CreateServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateServiceAccount indicates an expected call of CreateServiceAccount.
func (mr *MockAuthServiceClientMockRecorder) CreateServiceAccount(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateServiceAccount", reflect.TypeOf((*MockAuthServiceClient)(nil).CreateServiceAccount), varargs...)
}

// CreateServiceAccountAPIKey mocks base method.
func (m *MockAuthServiceClient) CreateServiceAccountAPIKey(ctx context.Context, in *authservice.CreateServiceAccountAPIKeyRequest, opts ...grpc.CallOption) (*authservice.CreateServiceAccountAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateServiceAccountAPIKey", varargs...)
	ret0, _ := ret[0].(*authservice.CreateServiceAccountAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateServiceAccountAPIKey indicates an expected call of CreateServiceAccountAPIKey.
func (mr *MockAuthServiceClientMockRecorder) CreateServiceAccountAPIKey(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateServiceAccountAPIKey", reflect.TypeOf((*MockAuthServiceClient)(nil).CreateServiceAccountAPIKey), varargs...)
}

// DeleteAPIKey mocks base method.
func (m *MockAuthServiceClient) DeleteAPIKey(ctx context.Context, in *authservice.DeleteAPIKeyRequest, opts ...grpc.CallOption) (*authservice.DeleteAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteAPIKey", varargs...)
	ret0, _ := ret[0].(*authservice.DeleteAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteAPIKey indicates an expected call of DeleteAPIKey.
func (mr *MockAuthServiceClientMockRecorder) DeleteAPIKey(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAPIKey", reflect.TypeOf((*MockAuthServiceClient)(nil).DeleteAPIKey), varargs...)
}

// DeleteServiceAccount mocks base method.
func (m *MockAuthServiceClient) DeleteServiceAccount(ctx context.Context, in *authservice.DeleteServiceAccountRequest, opts ...grpc.CallOption) (*authservice.DeleteServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteServiceAccount", varargs...)
	ret0, _ := ret[0].(*authservice.DeleteServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteServiceAccount indicates an expected call of DeleteServiceAccount.
func (mr *MockAuthServiceClientMockRecorder) DeleteServiceAccount(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteServiceAccount", reflect.TypeOf((*MockAuthServiceClient)(nil).DeleteServiceAccount), varargs...)
}

// DeleteUser mocks base method.
func (m *MockAuthServiceClient) DeleteUser(ctx context.Context, in *authservice.DeleteUserRequest, opts ...grpc.CallOption) (*authservice.DeleteUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteUser", varargs...)
	ret0, _ := ret[0].(*authservice.DeleteUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockAuthServiceClientMockRecorder) DeleteUser(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockAuthServiceClient)(nil).DeleteUser), varargs...)
}

// GetAPIKey mocks base method.
func (m *MockAuthServiceClient) GetAPIKey(ctx context.Context, in *authservice.GetAPIKeyRequest, opts ...grpc.CallOption) (*authservice.GetAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetAPIKey", varargs...)
	ret0, _ := ret[0].(*authservice.GetAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAPIKey indicates an expected call of GetAPIKey.
func (mr *MockAuthServiceClientMockRecorder) GetAPIKey(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAPIKey", reflect.TypeOf((*MockAuthServiceClient)(nil).GetAPIKey), varargs...)
}

// GetAPIKeys mocks base method.
func (m *MockAuthServiceClient) GetAPIKeys(ctx context.Context, in *authservice.GetAPIKeysRequest, opts ...grpc.CallOption) (*authservice.GetAPIKeysResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetAPIKeys", varargs...)
	ret0, _ := ret[0].(*authservice.GetAPIKeysResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAPIKeys indicates an expected call of GetAPIKeys.
func (mr *MockAuthServiceClientMockRecorder) GetAPIKeys(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAPIKeys", reflect.TypeOf((*MockAuthServiceClient)(nil).GetAPIKeys), varargs...)
}

// GetRole mocks base method.
func (m *MockAuthServiceClient) GetRole(ctx context.Context, in *authservice.GetRoleRequest, opts ...grpc.CallOption) (*authservice.GetRoleResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRole", varargs...)
	ret0, _ := ret[0].(*authservice.GetRoleResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRole indicates an expected call of GetRole.
func (mr *MockAuthServiceClientMockRecorder) GetRole(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRole", reflect.TypeOf((*MockAuthServiceClient)(nil).GetRole), varargs...)
}

// GetRoles mocks base method.
func (m *MockAuthServiceClient) GetRoles(ctx context.Context, in *authservice.GetRolesRequest, opts ...grpc.CallOption) (*authservice.GetRolesResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRoles", varargs...)
	ret0, _ := ret[0].(*authservice.GetRolesResponse)
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
func (m *MockAuthServiceClient) GetRolesByPermissions(ctx context.Context, in *authservice.GetRolesByPermissionsRequest, opts ...grpc.CallOption) (*authservice.GetRolesByPermissionsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRolesByPermissions", varargs...)
	ret0, _ := ret[0].(*authservice.GetRolesByPermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRolesByPermissions indicates an expected call of GetRolesByPermissions.
func (mr *MockAuthServiceClientMockRecorder) GetRolesByPermissions(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRolesByPermissions", reflect.TypeOf((*MockAuthServiceClient)(nil).GetRolesByPermissions), varargs...)
}

// GetServiceAccount mocks base method.
func (m *MockAuthServiceClient) GetServiceAccount(ctx context.Context, in *authservice.GetServiceAccountRequest, opts ...grpc.CallOption) (*authservice.GetServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetServiceAccount", varargs...)
	ret0, _ := ret[0].(*authservice.GetServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetServiceAccount indicates an expected call of GetServiceAccount.
func (mr *MockAuthServiceClientMockRecorder) GetServiceAccount(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceAccount", reflect.TypeOf((*MockAuthServiceClient)(nil).GetServiceAccount), varargs...)
}

// GetServiceAccounts mocks base method.
func (m *MockAuthServiceClient) GetServiceAccounts(ctx context.Context, in *authservice.GetServiceAccountsRequest, opts ...grpc.CallOption) (*authservice.GetServiceAccountsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetServiceAccounts", varargs...)
	ret0, _ := ret[0].(*authservice.GetServiceAccountsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetServiceAccounts indicates an expected call of GetServiceAccounts.
func (mr *MockAuthServiceClientMockRecorder) GetServiceAccounts(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceAccounts", reflect.TypeOf((*MockAuthServiceClient)(nil).GetServiceAccounts), varargs...)
}

// GetUser mocks base method.
func (m *MockAuthServiceClient) GetUser(ctx context.Context, in *authservice.GetUserRequest, opts ...grpc.CallOption) (*authservice.GetUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUser", varargs...)
	ret0, _ := ret[0].(*authservice.GetUserResponse)
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
func (m *MockAuthServiceClient) GetUsers(ctx context.Context, in *authservice.GetUsersRequest, opts ...grpc.CallOption) (*authservice.GetUsersResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUsers", varargs...)
	ret0, _ := ret[0].(*authservice.GetUsersResponse)
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
func (m *MockAuthServiceClient) InviteUsers(ctx context.Context, in *authservice.InviteUsersRequest, opts ...grpc.CallOption) (*authservice.InviteUsersResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "InviteUsers", varargs...)
	ret0, _ := ret[0].(*authservice.InviteUsersResponse)
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
func (m *MockAuthServiceClient) ResendUserInvite(ctx context.Context, in *authservice.ResendUserInviteRequest, opts ...grpc.CallOption) (*authservice.ResendUserInviteResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ResendUserInvite", varargs...)
	ret0, _ := ret[0].(*authservice.ResendUserInviteResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResendUserInvite indicates an expected call of ResendUserInvite.
func (mr *MockAuthServiceClientMockRecorder) ResendUserInvite(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResendUserInvite", reflect.TypeOf((*MockAuthServiceClient)(nil).ResendUserInvite), varargs...)
}

// UpdateAPIKey mocks base method.
func (m *MockAuthServiceClient) UpdateAPIKey(ctx context.Context, in *authservice.UpdateAPIKeyRequest, opts ...grpc.CallOption) (*authservice.UpdateAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateAPIKey", varargs...)
	ret0, _ := ret[0].(*authservice.UpdateAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateAPIKey indicates an expected call of UpdateAPIKey.
func (mr *MockAuthServiceClientMockRecorder) UpdateAPIKey(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateAPIKey", reflect.TypeOf((*MockAuthServiceClient)(nil).UpdateAPIKey), varargs...)
}

// UpdateIdentityNamespacePermissions mocks base method.
func (m *MockAuthServiceClient) UpdateIdentityNamespacePermissions(ctx context.Context, in *authservice.UpdateIdentityNamespacePermissionsRequest, opts ...grpc.CallOption) (*authservice.UpdateIdentityNamespacePermissionsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateIdentityNamespacePermissions", varargs...)
	ret0, _ := ret[0].(*authservice.UpdateIdentityNamespacePermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateIdentityNamespacePermissions indicates an expected call of UpdateIdentityNamespacePermissions.
func (mr *MockAuthServiceClientMockRecorder) UpdateIdentityNamespacePermissions(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateIdentityNamespacePermissions", reflect.TypeOf((*MockAuthServiceClient)(nil).UpdateIdentityNamespacePermissions), varargs...)
}

// UpdateServiceAccount mocks base method.
func (m *MockAuthServiceClient) UpdateServiceAccount(ctx context.Context, in *authservice.UpdateServiceAccountRequest, opts ...grpc.CallOption) (*authservice.UpdateServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateServiceAccount", varargs...)
	ret0, _ := ret[0].(*authservice.UpdateServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateServiceAccount indicates an expected call of UpdateServiceAccount.
func (mr *MockAuthServiceClientMockRecorder) UpdateServiceAccount(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateServiceAccount", reflect.TypeOf((*MockAuthServiceClient)(nil).UpdateServiceAccount), varargs...)
}

// UpdateUser mocks base method.
func (m *MockAuthServiceClient) UpdateUser(ctx context.Context, in *authservice.UpdateUserRequest, opts ...grpc.CallOption) (*authservice.UpdateUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateUser", varargs...)
	ret0, _ := ret[0].(*authservice.UpdateUserResponse)
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
func (m *MockAuthServiceClient) UpdateUserNamespacePermissions(ctx context.Context, in *authservice.UpdateUserNamespacePermissionsRequest, opts ...grpc.CallOption) (*authservice.UpdateUserNamespacePermissionsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateUserNamespacePermissions", varargs...)
	ret0, _ := ret[0].(*authservice.UpdateUserNamespacePermissionsResponse)
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

// CreateAPIKey mocks base method.
func (m *MockAuthServiceServer) CreateAPIKey(arg0 context.Context, arg1 *authservice.CreateAPIKeyRequest) (*authservice.CreateAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAPIKey", arg0, arg1)
	ret0, _ := ret[0].(*authservice.CreateAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAPIKey indicates an expected call of CreateAPIKey.
func (mr *MockAuthServiceServerMockRecorder) CreateAPIKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAPIKey", reflect.TypeOf((*MockAuthServiceServer)(nil).CreateAPIKey), arg0, arg1)
}

// CreateServiceAccount mocks base method.
func (m *MockAuthServiceServer) CreateServiceAccount(arg0 context.Context, arg1 *authservice.CreateServiceAccountRequest) (*authservice.CreateServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateServiceAccount", arg0, arg1)
	ret0, _ := ret[0].(*authservice.CreateServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateServiceAccount indicates an expected call of CreateServiceAccount.
func (mr *MockAuthServiceServerMockRecorder) CreateServiceAccount(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateServiceAccount", reflect.TypeOf((*MockAuthServiceServer)(nil).CreateServiceAccount), arg0, arg1)
}

// CreateServiceAccountAPIKey mocks base method.
func (m *MockAuthServiceServer) CreateServiceAccountAPIKey(arg0 context.Context, arg1 *authservice.CreateServiceAccountAPIKeyRequest) (*authservice.CreateServiceAccountAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateServiceAccountAPIKey", arg0, arg1)
	ret0, _ := ret[0].(*authservice.CreateServiceAccountAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateServiceAccountAPIKey indicates an expected call of CreateServiceAccountAPIKey.
func (mr *MockAuthServiceServerMockRecorder) CreateServiceAccountAPIKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateServiceAccountAPIKey", reflect.TypeOf((*MockAuthServiceServer)(nil).CreateServiceAccountAPIKey), arg0, arg1)
}

// DeleteAPIKey mocks base method.
func (m *MockAuthServiceServer) DeleteAPIKey(arg0 context.Context, arg1 *authservice.DeleteAPIKeyRequest) (*authservice.DeleteAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAPIKey", arg0, arg1)
	ret0, _ := ret[0].(*authservice.DeleteAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteAPIKey indicates an expected call of DeleteAPIKey.
func (mr *MockAuthServiceServerMockRecorder) DeleteAPIKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAPIKey", reflect.TypeOf((*MockAuthServiceServer)(nil).DeleteAPIKey), arg0, arg1)
}

// DeleteServiceAccount mocks base method.
func (m *MockAuthServiceServer) DeleteServiceAccount(arg0 context.Context, arg1 *authservice.DeleteServiceAccountRequest) (*authservice.DeleteServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteServiceAccount", arg0, arg1)
	ret0, _ := ret[0].(*authservice.DeleteServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteServiceAccount indicates an expected call of DeleteServiceAccount.
func (mr *MockAuthServiceServerMockRecorder) DeleteServiceAccount(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteServiceAccount", reflect.TypeOf((*MockAuthServiceServer)(nil).DeleteServiceAccount), arg0, arg1)
}

// DeleteUser mocks base method.
func (m *MockAuthServiceServer) DeleteUser(arg0 context.Context, arg1 *authservice.DeleteUserRequest) (*authservice.DeleteUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", arg0, arg1)
	ret0, _ := ret[0].(*authservice.DeleteUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *MockAuthServiceServerMockRecorder) DeleteUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*MockAuthServiceServer)(nil).DeleteUser), arg0, arg1)
}

// GetAPIKey mocks base method.
func (m *MockAuthServiceServer) GetAPIKey(arg0 context.Context, arg1 *authservice.GetAPIKeyRequest) (*authservice.GetAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAPIKey", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAPIKey indicates an expected call of GetAPIKey.
func (mr *MockAuthServiceServerMockRecorder) GetAPIKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAPIKey", reflect.TypeOf((*MockAuthServiceServer)(nil).GetAPIKey), arg0, arg1)
}

// GetAPIKeys mocks base method.
func (m *MockAuthServiceServer) GetAPIKeys(arg0 context.Context, arg1 *authservice.GetAPIKeysRequest) (*authservice.GetAPIKeysResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAPIKeys", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetAPIKeysResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAPIKeys indicates an expected call of GetAPIKeys.
func (mr *MockAuthServiceServerMockRecorder) GetAPIKeys(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAPIKeys", reflect.TypeOf((*MockAuthServiceServer)(nil).GetAPIKeys), arg0, arg1)
}

// GetRole mocks base method.
func (m *MockAuthServiceServer) GetRole(arg0 context.Context, arg1 *authservice.GetRoleRequest) (*authservice.GetRoleResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRole", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetRoleResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRole indicates an expected call of GetRole.
func (mr *MockAuthServiceServerMockRecorder) GetRole(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRole", reflect.TypeOf((*MockAuthServiceServer)(nil).GetRole), arg0, arg1)
}

// GetRoles mocks base method.
func (m *MockAuthServiceServer) GetRoles(arg0 context.Context, arg1 *authservice.GetRolesRequest) (*authservice.GetRolesResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRoles", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetRolesResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRoles indicates an expected call of GetRoles.
func (mr *MockAuthServiceServerMockRecorder) GetRoles(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRoles", reflect.TypeOf((*MockAuthServiceServer)(nil).GetRoles), arg0, arg1)
}

// GetRolesByPermissions mocks base method.
func (m *MockAuthServiceServer) GetRolesByPermissions(arg0 context.Context, arg1 *authservice.GetRolesByPermissionsRequest) (*authservice.GetRolesByPermissionsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRolesByPermissions", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetRolesByPermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRolesByPermissions indicates an expected call of GetRolesByPermissions.
func (mr *MockAuthServiceServerMockRecorder) GetRolesByPermissions(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRolesByPermissions", reflect.TypeOf((*MockAuthServiceServer)(nil).GetRolesByPermissions), arg0, arg1)
}

// GetServiceAccount mocks base method.
func (m *MockAuthServiceServer) GetServiceAccount(arg0 context.Context, arg1 *authservice.GetServiceAccountRequest) (*authservice.GetServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServiceAccount", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetServiceAccount indicates an expected call of GetServiceAccount.
func (mr *MockAuthServiceServerMockRecorder) GetServiceAccount(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceAccount", reflect.TypeOf((*MockAuthServiceServer)(nil).GetServiceAccount), arg0, arg1)
}

// GetServiceAccounts mocks base method.
func (m *MockAuthServiceServer) GetServiceAccounts(arg0 context.Context, arg1 *authservice.GetServiceAccountsRequest) (*authservice.GetServiceAccountsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServiceAccounts", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetServiceAccountsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetServiceAccounts indicates an expected call of GetServiceAccounts.
func (mr *MockAuthServiceServerMockRecorder) GetServiceAccounts(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceAccounts", reflect.TypeOf((*MockAuthServiceServer)(nil).GetServiceAccounts), arg0, arg1)
}

// GetUser mocks base method.
func (m *MockAuthServiceServer) GetUser(arg0 context.Context, arg1 *authservice.GetUserRequest) (*authservice.GetUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *MockAuthServiceServerMockRecorder) GetUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*MockAuthServiceServer)(nil).GetUser), arg0, arg1)
}

// GetUsers mocks base method.
func (m *MockAuthServiceServer) GetUsers(arg0 context.Context, arg1 *authservice.GetUsersRequest) (*authservice.GetUsersResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUsers", arg0, arg1)
	ret0, _ := ret[0].(*authservice.GetUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *MockAuthServiceServerMockRecorder) GetUsers(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*MockAuthServiceServer)(nil).GetUsers), arg0, arg1)
}

// InviteUsers mocks base method.
func (m *MockAuthServiceServer) InviteUsers(arg0 context.Context, arg1 *authservice.InviteUsersRequest) (*authservice.InviteUsersResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InviteUsers", arg0, arg1)
	ret0, _ := ret[0].(*authservice.InviteUsersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InviteUsers indicates an expected call of InviteUsers.
func (mr *MockAuthServiceServerMockRecorder) InviteUsers(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InviteUsers", reflect.TypeOf((*MockAuthServiceServer)(nil).InviteUsers), arg0, arg1)
}

// ResendUserInvite mocks base method.
func (m *MockAuthServiceServer) ResendUserInvite(arg0 context.Context, arg1 *authservice.ResendUserInviteRequest) (*authservice.ResendUserInviteResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResendUserInvite", arg0, arg1)
	ret0, _ := ret[0].(*authservice.ResendUserInviteResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ResendUserInvite indicates an expected call of ResendUserInvite.
func (mr *MockAuthServiceServerMockRecorder) ResendUserInvite(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResendUserInvite", reflect.TypeOf((*MockAuthServiceServer)(nil).ResendUserInvite), arg0, arg1)
}

// UpdateAPIKey mocks base method.
func (m *MockAuthServiceServer) UpdateAPIKey(arg0 context.Context, arg1 *authservice.UpdateAPIKeyRequest) (*authservice.UpdateAPIKeyResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateAPIKey", arg0, arg1)
	ret0, _ := ret[0].(*authservice.UpdateAPIKeyResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateAPIKey indicates an expected call of UpdateAPIKey.
func (mr *MockAuthServiceServerMockRecorder) UpdateAPIKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateAPIKey", reflect.TypeOf((*MockAuthServiceServer)(nil).UpdateAPIKey), arg0, arg1)
}

// UpdateIdentityNamespacePermissions mocks base method.
func (m *MockAuthServiceServer) UpdateIdentityNamespacePermissions(arg0 context.Context, arg1 *authservice.UpdateIdentityNamespacePermissionsRequest) (*authservice.UpdateIdentityNamespacePermissionsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateIdentityNamespacePermissions", arg0, arg1)
	ret0, _ := ret[0].(*authservice.UpdateIdentityNamespacePermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateIdentityNamespacePermissions indicates an expected call of UpdateIdentityNamespacePermissions.
func (mr *MockAuthServiceServerMockRecorder) UpdateIdentityNamespacePermissions(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateIdentityNamespacePermissions", reflect.TypeOf((*MockAuthServiceServer)(nil).UpdateIdentityNamespacePermissions), arg0, arg1)
}

// UpdateServiceAccount mocks base method.
func (m *MockAuthServiceServer) UpdateServiceAccount(arg0 context.Context, arg1 *authservice.UpdateServiceAccountRequest) (*authservice.UpdateServiceAccountResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateServiceAccount", arg0, arg1)
	ret0, _ := ret[0].(*authservice.UpdateServiceAccountResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateServiceAccount indicates an expected call of UpdateServiceAccount.
func (mr *MockAuthServiceServerMockRecorder) UpdateServiceAccount(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateServiceAccount", reflect.TypeOf((*MockAuthServiceServer)(nil).UpdateServiceAccount), arg0, arg1)
}

// UpdateUser mocks base method.
func (m *MockAuthServiceServer) UpdateUser(arg0 context.Context, arg1 *authservice.UpdateUserRequest) (*authservice.UpdateUserResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", arg0, arg1)
	ret0, _ := ret[0].(*authservice.UpdateUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *MockAuthServiceServerMockRecorder) UpdateUser(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*MockAuthServiceServer)(nil).UpdateUser), arg0, arg1)
}

// UpdateUserNamespacePermissions mocks base method.
func (m *MockAuthServiceServer) UpdateUserNamespacePermissions(arg0 context.Context, arg1 *authservice.UpdateUserNamespacePermissionsRequest) (*authservice.UpdateUserNamespacePermissionsResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserNamespacePermissions", arg0, arg1)
	ret0, _ := ret[0].(*authservice.UpdateUserNamespacePermissionsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUserNamespacePermissions indicates an expected call of UpdateUserNamespacePermissions.
func (mr *MockAuthServiceServerMockRecorder) UpdateUserNamespacePermissions(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserNamespacePermissions", reflect.TypeOf((*MockAuthServiceServer)(nil).UpdateUserNamespacePermissions), arg0, arg1)
}
