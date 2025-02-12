// Code generated by MockGen. DO NOT EDIT.
// Source: api/requestservice/v1/service.pb.go

// Package apimock is a generated GoMock package.
package apimock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	requestservice "github.com/temporalio/saas-proto/protogen/api/requestservice/v1"
	grpc "google.golang.org/grpc"
)

// MockRequestServiceClient is a mock of RequestServiceClient interface.
type MockRequestServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockRequestServiceClientMockRecorder
}

// MockRequestServiceClientMockRecorder is the mock recorder for MockRequestServiceClient.
type MockRequestServiceClientMockRecorder struct {
	mock *MockRequestServiceClient
}

// NewMockRequestServiceClient creates a new mock instance.
func NewMockRequestServiceClient(ctrl *gomock.Controller) *MockRequestServiceClient {
	mock := &MockRequestServiceClient{ctrl: ctrl}
	mock.recorder = &MockRequestServiceClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRequestServiceClient) EXPECT() *MockRequestServiceClientMockRecorder {
	return m.recorder
}

// GetRequestStatus mocks base method.
func (m *MockRequestServiceClient) GetRequestStatus(ctx context.Context, in *requestservice.GetRequestStatusRequest, opts ...grpc.CallOption) (*requestservice.GetRequestStatusResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetRequestStatus", varargs...)
	ret0, _ := ret[0].(*requestservice.GetRequestStatusResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRequestStatus indicates an expected call of GetRequestStatus.
func (mr *MockRequestServiceClientMockRecorder) GetRequestStatus(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestStatus", reflect.TypeOf((*MockRequestServiceClient)(nil).GetRequestStatus), varargs...)
}

// MockRequestServiceServer is a mock of RequestServiceServer interface.
type MockRequestServiceServer struct {
	ctrl     *gomock.Controller
	recorder *MockRequestServiceServerMockRecorder
}

// MockRequestServiceServerMockRecorder is the mock recorder for MockRequestServiceServer.
type MockRequestServiceServerMockRecorder struct {
	mock *MockRequestServiceServer
}

// NewMockRequestServiceServer creates a new mock instance.
func NewMockRequestServiceServer(ctrl *gomock.Controller) *MockRequestServiceServer {
	mock := &MockRequestServiceServer{ctrl: ctrl}
	mock.recorder = &MockRequestServiceServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRequestServiceServer) EXPECT() *MockRequestServiceServerMockRecorder {
	return m.recorder
}

// GetRequestStatus mocks base method.
func (m *MockRequestServiceServer) GetRequestStatus(arg0 context.Context, arg1 *requestservice.GetRequestStatusRequest) (*requestservice.GetRequestStatusResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestStatus", arg0, arg1)
	ret0, _ := ret[0].(*requestservice.GetRequestStatusResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRequestStatus indicates an expected call of GetRequestStatus.
func (mr *MockRequestServiceServerMockRecorder) GetRequestStatus(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestStatus", reflect.TypeOf((*MockRequestServiceServer)(nil).GetRequestStatus), arg0, arg1)
}
