package app

import (
	"encoding/json"
	"errors"
	"github.com/temporalio/tcld/protogen/api/namespace/v1"
	"strings"
)

const https = "https"

type codecServer struct {
	Endpoint           string `json:"Endpoint" validate:"required"`
	PassAccessToken    bool   `json:"PassAccessToken"`
	IncludeCredentials bool   `json:"IncludeCredentials"`
}

func parseAndConvertCodecServer(codecServerJson string) (*namespace.CodecServerPropertySpec, error) {
	var codec codecServer
	if err := json.Unmarshal([]byte(codecServerJson), &codec); err != nil {
		return &namespace.CodecServerPropertySpec{}, err
	}

	err := validateCodec(codec)
	if err != nil {
		return &namespace.CodecServerPropertySpec{}, err
	}
	return &namespace.CodecServerPropertySpec{
		Endpoint:           codec.Endpoint,
		PassAccessToken:    codec.PassAccessToken,
		IncludeCredentials: codec.IncludeCredentials,
	}, nil
}

func validateCodec(codec codecServer) error {
	if codec.Endpoint == "" {
		return errors.New("field Endpoint has to be specified")
	}
	if !strings.HasPrefix(codec.Endpoint, https) {
		return errors.New("field Endpoint has to use https")
	}
	return nil
}
