package app

import (
	"fmt"

	"github.com/gogo/protobuf/proto"
)

type gogoProtoCodec struct{}

func (gogoProtoCodec) Name() string {
	return "proto"
}

func (gogoProtoCodec) Marshal(value interface{}) ([]byte, error) {
	message, ok := value.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("cannot marshal %T as a protobuf message", value)
	}
	return proto.Marshal(message)
}

func (gogoProtoCodec) Unmarshal(data []byte, value interface{}) error {
	message, ok := value.(proto.Message)
	if !ok {
		return fmt.Errorf("cannot unmarshal %T as a protobuf message", value)
	}
	return proto.Unmarshal(data, message)
}
