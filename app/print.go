package app

import (
	"encoding/json"
	"fmt"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/proto"
)

func FormatJson(i interface{}) (string, error) {
	resJson, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v\n", string(resJson)), nil
}

func PrintObj(i interface{}) error {
	resJson, err := FormatJson(i)
	if err != nil {
		return err
	}
	fmt.Printf("%s", string(resJson))
	return nil
}

func PrintProto(m proto.Message) error {
	marshaler := jsonpb.Marshaler{
		Indent:       "\t",
		EmitDefaults: true,
	}
	ser, err := marshaler.MarshalToString(m)
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", ser)
	return nil
}
