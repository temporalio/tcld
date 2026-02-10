package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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

func serializeProto(m any) (string, error) {
	if m == nil || (reflect.ValueOf(m).Kind() == reflect.Ptr && reflect.ValueOf(m).IsNil()) {
		return "", fmt.Errorf("nil message")
	}
	if pm, ok := m.(proto.Message); ok {
		marshaler := protojson.MarshalOptions{
			Indent:          "\t",
			EmitUnpopulated: true,
		}
		b, err := marshaler.Marshal(pm)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	b, err := json.MarshalIndent(m, "", "\t")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func PrintProto(m any) error {
	ser, err := serializeProto(m)
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", ser)
	return nil
}

func PrintProtoSlice(name string, ms []any) error {

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
