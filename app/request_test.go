package app

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/requestservice/v1"
	requestservicemock "github.com/temporalio/tcld/protogen/apimock/requestservice/v1"
	"github.com/urfave/cli/v2"
)

func TestRequest(t *testing.T) {
	suite.Run(t, new(RequestTestSuite))
}

type RequestTestSuite struct {
	suite.Suite
	cliApp      *cli.App
	mockCtrl    *gomock.Controller
	mockService *requestservicemock.MockRequestServiceClient
}

func (s *RequestTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockService = requestservicemock.NewMockRequestServiceClient(s.mockCtrl)
	out, err := NewRequestCommand(func(ctx *cli.Context) (*RequestClient, error) {
		return &RequestClient{
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

func (s *RequestTestSuite) AfterTest(suiteName, testName string) {
	s.mockCtrl.Finish()
}

func (s *RequestTestSuite) RunCmd(args ...string) error {
	return s.cliApp.Run(append([]string{"tcld"}, args...))
}

func (s *RequestTestSuite) TestGet() {

	s.Error(s.RunCmd("request", "get"))

	s.mockService.EXPECT().GetRequestStatus(gomock.Any(), &requestservice.GetRequestStatusRequest{
		RequestId: "req1",
	}).Return(nil, errors.New("some error")).Times(1)
	s.Error(s.RunCmd("request", "get", "--request-id", "req1"))

	s.mockService.EXPECT().GetRequestStatus(gomock.Any(), &requestservice.GetRequestStatusRequest{
		RequestId: "req1",
	}).Return(&requestservice.GetRequestStatusResponse{}, nil).Times(1)
	s.NoError(s.RunCmd("request", "get", "--request-id", "req1"))
}
