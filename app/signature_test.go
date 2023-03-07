package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/temporalio/tcld/protogen/api/request/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/temporalio/tcld/protogen/api/requestservice/v1"
)

const (
	testKeyID       = "test-key-id"
	testServiceName = "test-service-name"
	testSecretKey   = "test-secret-key"
)

type (
	RequestSignatureTestSuite struct {
		suite.Suite
		lis *bufconn.Listener
	}
	testServer struct{}
)

func TestRequestSignature(t *testing.T) {
	suite.Run(t, new(RequestSignatureTestSuite))
}

func (s *RequestSignatureTestSuite) SetupTest() {
	s.lis = bufconn.Listen(1024)
	grpcServer := grpc.NewServer()
	requestservice.RegisterRequestServiceServer(grpcServer, &testServer{})
	go func() {
		s.NoError(grpcServer.Serve(s.lis))
	}()
}

func (s *RequestSignatureTestSuite) TestRequestSignature() {
	ctx := context.Background()
	conn, err := grpc.DialContext(
		ctx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return s.lis.Dial()
		}),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(
			getRequestSignatureInterceptor(
				testServiceName,
				testKeyID,
				testSecretKey,
				true,
			),
		),
	)
	s.NoError(err)
	defer conn.Close()
	client := requestservice.NewRequestServiceClient(conn)
	_, err = client.GetRequestStatus(ctx, &requestservice.GetRequestStatusRequest{
		RequestId: "test-request-id",
	})
	s.NoError(err)
}

func (s *testServer) GetRequestStatus(ctx context.Context, req *requestservice.GetRequestStatusRequest) (*requestservice.GetRequestStatusResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		keyID := getHeaderValue(md, TmprlAPIKeyIDHeader)
		if keyID != testKeyID {
			return nil, fmt.Errorf("key id does not match: %s %s", keyID, testKeyID)
		}
		algo := getHeaderValue(md, TmprlRequestSignatureAlgorithmHeader)
		if algo != DefaultRequestSignatureAlgorithm {
			return nil, fmt.Errorf("request signature algorithm does not match: %s %s", algo, DefaultRequestSignatureAlgorithm)
		}
		requestDateTime := getHeaderValue(md, TmprlRequestDatetimeHeader)
		_, err := time.Parse(time.RFC3339, requestDateTime)
		if err != nil {
			return nil, err
		}
		sig := getHeaderValue(md, TmprlRequestSignatureHeader)
		if len(sig) == 0 {
			return nil, errors.New("signature not found")
		}
	}
	return &requestservice.GetRequestStatusResponse{
		RequestStatus: &request.RequestStatus{
			RequestId: "test-request-id",
			State:     request.STATE_FULFILLED,
		},
	}, nil
}

func getHeaderValue(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}
