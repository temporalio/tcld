package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log"
	"path"
	"time"
)

const (
	TmprlRequestSignatureHeader          = "tmprl-request-signature"
	TmprlRequestSignatureAlgorithmHeader = "tmprl-request-signature-algorithm"
	TmprlRequestDatetimeHeader           = "tmprl-request-datetime"
	TmprlAPIKeyIDHeader                  = "tmprl-api-key-id"
	DefaultRequestSignatureAlgorithm     = "tmprl-hmac-sha256"
	// requestSignatureFormat requires each of the following data on a newline
	// KeyID
	// RequestSignatureAlgorithm
	// RequestDatetime
	// ActionName
	requestSignatureFormat = "%s\n%s\n%s\n%s"
)

func getRequestSignatureInterceptor(
	serviceName string,
	keyID string,
	secretKey string,
	enableDebugLogs bool,
) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req interface{}, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if len(serviceName) > 0 && len(keyID) > 0 && len(secretKey) > 0 {
			requestDatetime := time.Now().Format(time.RFC3339)
			action := fmt.Sprintf("%s:%s", serviceName, path.Base(method))
			message := fmt.Sprintf(
				requestSignatureFormat,
				keyID,
				DefaultRequestSignatureAlgorithm,
				requestDatetime,
				action,
			)
			if enableDebugLogs {
				log.Printf("request signature message: \n%s", message)
			}
			signature, err := generateSignature(message, secretKey)
			if err != nil {
				return err
			}
			if enableDebugLogs {
				log.Printf("request signature hash: \n%s", signature)
			}
			ctx = metadata.AppendToOutgoingContext(
				ctx,
				TmprlAPIKeyIDHeader, keyID,
				TmprlRequestDatetimeHeader, requestDatetime,
				TmprlRequestSignatureAlgorithmHeader, DefaultRequestSignatureAlgorithm,
				TmprlRequestSignatureHeader, signature,
			)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func generateSignature(data string, key string) (string, error) {
	h := hmac.New(sha256.New, []byte(key))
	_, err := h.Write([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
