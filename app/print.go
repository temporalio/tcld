package app

import (
	"bytes"
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

func serializeProto(m proto.Message) (string, error) {
	marshaler := jsonpb.Marshaler{
		Indent:       "\t",
		EmitDefaults: true,
	}
	ser, err := marshaler.MarshalToString(m)
	if err != nil {
		return "", err
	}
	return ser, nil
}

func PrintProto(m proto.Message) error {
	ser, err := serializeProto(m)
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", ser)
	return nil
}

func PrintProtoSlice(name string, ms []proto.Message) error {

	result := fmt.Sprintf("{\"%s\":[", name)
	for i := range ms {
		ser, err := serializeProto(ms[i])
		if err != nil {
			return err
		}
		if i != 0 {
			result += ","
		}
		result += ser
	}
	result += "]}"

	var out bytes.Buffer
	err := json.Indent(&out, []byte(result), "", "\t")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", out.String())
	return nil
}
