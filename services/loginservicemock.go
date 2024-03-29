// Code generated by MockGen. DO NOT EDIT.
// Source: services/loginservice.go

// Package services is a generated GoMock package.
package services

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockLoginService is a mock of LoginService interface.
type MockLoginService struct {
	ctrl     *gomock.Controller
	recorder *MockLoginServiceMockRecorder
}

// MockLoginServiceMockRecorder is the mock recorder for MockLoginService.
type MockLoginServiceMockRecorder struct {
	mock *MockLoginService
}

// NewMockLoginService creates a new mock instance.
func NewMockLoginService(ctrl *gomock.Controller) *MockLoginService {
	mock := &MockLoginService{ctrl: ctrl}
	mock.recorder = &MockLoginServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLoginService) EXPECT() *MockLoginServiceMockRecorder {
	return m.recorder
}

// DeleteConfigFile mocks base method.
func (m *MockLoginService) DeleteConfigFile(configPath string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteConfigFile", configPath)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteConfigFile indicates an expected call of DeleteConfigFile.
func (mr *MockLoginServiceMockRecorder) DeleteConfigFile(configPath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteConfigFile", reflect.TypeOf((*MockLoginService)(nil).DeleteConfigFile), configPath)
}

// OpenBrowser mocks base method.
func (m *MockLoginService) OpenBrowser(URL string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenBrowser", URL)
	ret0, _ := ret[0].(error)
	return ret0
}

// OpenBrowser indicates an expected call of OpenBrowser.
func (mr *MockLoginServiceMockRecorder) OpenBrowser(URL interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenBrowser", reflect.TypeOf((*MockLoginService)(nil).OpenBrowser), URL)
}

// WriteToConfigFile mocks base method.
func (m *MockLoginService) WriteToConfigFile(configPath, data string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteToConfigFile", configPath, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// WriteToConfigFile indicates an expected call of WriteToConfigFile.
func (mr *MockLoginServiceMockRecorder) WriteToConfigFile(configPath, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteToConfigFile", reflect.TypeOf((*MockLoginService)(nil).WriteToConfigFile), configPath, data)
}
