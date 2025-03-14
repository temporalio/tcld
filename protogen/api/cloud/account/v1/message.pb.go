// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: temporal/api/cloud/account/v1/message.proto

package account

import (
	bytes "bytes"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	v1 "github.com/temporalio/tcld/protogen/api/cloud/resource/v1"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type MetricsSpec struct {
	// The ca cert(s) in PEM format that clients connecting to the metrics endpoint can use for authentication.
	// This must only be one value, but the CA can have a chain.
	AcceptedClientCa []byte `protobuf:"bytes,2,opt,name=accepted_client_ca,json=acceptedClientCa,proto3" json:"accepted_client_ca,omitempty"`
}

func (m *MetricsSpec) Reset()      { *m = MetricsSpec{} }
func (*MetricsSpec) ProtoMessage() {}
func (*MetricsSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_0da0883d6b494eb5, []int{0}
}
func (m *MetricsSpec) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MetricsSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MetricsSpec.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MetricsSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MetricsSpec.Merge(m, src)
}
func (m *MetricsSpec) XXX_Size() int {
	return m.Size()
}
func (m *MetricsSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_MetricsSpec.DiscardUnknown(m)
}

var xxx_messageInfo_MetricsSpec proto.InternalMessageInfo

func (m *MetricsSpec) GetAcceptedClientCa() []byte {
	if m != nil {
		return m.AcceptedClientCa
	}
	return nil
}

type AccountSpec struct {
	// The metrics specification for this account.
	// If not specified, metrics will not be enabled.
	Metrics *MetricsSpec `protobuf:"bytes,1,opt,name=metrics,proto3" json:"metrics,omitempty"`
}

func (m *AccountSpec) Reset()      { *m = AccountSpec{} }
func (*AccountSpec) ProtoMessage() {}
func (*AccountSpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_0da0883d6b494eb5, []int{1}
}
func (m *AccountSpec) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AccountSpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AccountSpec.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AccountSpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccountSpec.Merge(m, src)
}
func (m *AccountSpec) XXX_Size() int {
	return m.Size()
}
func (m *AccountSpec) XXX_DiscardUnknown() {
	xxx_messageInfo_AccountSpec.DiscardUnknown(m)
}

var xxx_messageInfo_AccountSpec proto.InternalMessageInfo

func (m *AccountSpec) GetMetrics() *MetricsSpec {
	if m != nil {
		return m.Metrics
	}
	return nil
}

type Metrics struct {
	// The prometheus metrics endpoint uri.
	// This is only populated when the metrics is enabled in the metrics specification.
	Uri string `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
}

func (m *Metrics) Reset()      { *m = Metrics{} }
func (*Metrics) ProtoMessage() {}
func (*Metrics) Descriptor() ([]byte, []int) {
	return fileDescriptor_0da0883d6b494eb5, []int{2}
}
func (m *Metrics) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Metrics) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Metrics.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Metrics) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Metrics.Merge(m, src)
}
func (m *Metrics) XXX_Size() int {
	return m.Size()
}
func (m *Metrics) XXX_DiscardUnknown() {
	xxx_messageInfo_Metrics.DiscardUnknown(m)
}

var xxx_messageInfo_Metrics proto.InternalMessageInfo

func (m *Metrics) GetUri() string {
	if m != nil {
		return m.Uri
	}
	return ""
}

type Account struct {
	// The id of the account.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The account specification.
	Spec *AccountSpec `protobuf:"bytes,2,opt,name=spec,proto3" json:"spec,omitempty"`
	// The current version of the account specification.
	// The next update operation will have to include this version.
	ResourceVersion string `protobuf:"bytes,3,opt,name=resource_version,json=resourceVersion,proto3" json:"resource_version,omitempty"`
	// The current state of the account.
	State v1.ResourceState `protobuf:"varint,4,opt,name=state,proto3,enum=temporal.api.cloud.resource.v1.ResourceState" json:"state,omitempty"`
	// The id of the async operation that is updating the account, if any.
	AsyncOperationId string `protobuf:"bytes,5,opt,name=async_operation_id,json=asyncOperationId,proto3" json:"async_operation_id,omitempty"`
	// Information related to metrics.
	Metrics *Metrics `protobuf:"bytes,6,opt,name=metrics,proto3" json:"metrics,omitempty"`
}

func (m *Account) Reset()      { *m = Account{} }
func (*Account) ProtoMessage() {}
func (*Account) Descriptor() ([]byte, []int) {
	return fileDescriptor_0da0883d6b494eb5, []int{3}
}
func (m *Account) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Account) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Account.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Account) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Account.Merge(m, src)
}
func (m *Account) XXX_Size() int {
	return m.Size()
}
func (m *Account) XXX_DiscardUnknown() {
	xxx_messageInfo_Account.DiscardUnknown(m)
}

var xxx_messageInfo_Account proto.InternalMessageInfo

func (m *Account) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Account) GetSpec() *AccountSpec {
	if m != nil {
		return m.Spec
	}
	return nil
}

func (m *Account) GetResourceVersion() string {
	if m != nil {
		return m.ResourceVersion
	}
	return ""
}

func (m *Account) GetState() v1.ResourceState {
	if m != nil {
		return m.State
	}
	return v1.RESOURCE_STATE_UNSPECIFIED
}

func (m *Account) GetAsyncOperationId() string {
	if m != nil {
		return m.AsyncOperationId
	}
	return ""
}

func (m *Account) GetMetrics() *Metrics {
	if m != nil {
		return m.Metrics
	}
	return nil
}

func init() {
	proto.RegisterType((*MetricsSpec)(nil), "temporal.api.cloud.account.v1.MetricsSpec")
	proto.RegisterType((*AccountSpec)(nil), "temporal.api.cloud.account.v1.AccountSpec")
	proto.RegisterType((*Metrics)(nil), "temporal.api.cloud.account.v1.Metrics")
	proto.RegisterType((*Account)(nil), "temporal.api.cloud.account.v1.Account")
}

func init() {
	proto.RegisterFile("temporal/api/cloud/account/v1/message.proto", fileDescriptor_0da0883d6b494eb5)
}

var fileDescriptor_0da0883d6b494eb5 = []byte{
	// 461 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0xcf, 0x8a, 0x13, 0x31,
	0x18, 0x9f, 0xcc, 0xfe, 0x29, 0xa6, 0xcb, 0x5a, 0x72, 0x1a, 0x14, 0x63, 0xa9, 0x20, 0xd5, 0x5d,
	0x33, 0x74, 0xbd, 0xcd, 0x82, 0xd8, 0xad, 0x17, 0x0f, 0x8b, 0xcb, 0x54, 0x7a, 0xf0, 0x32, 0xc4,
	0x4c, 0x58, 0x02, 0xed, 0x24, 0x24, 0x69, 0xc1, 0x9b, 0x8f, 0xe0, 0x63, 0x88, 0x6f, 0xe0, 0x1b,
	0x78, 0xec, 0x71, 0xc1, 0x8b, 0x9d, 0x5e, 0xc4, 0xd3, 0x3e, 0x82, 0x4c, 0x26, 0xe3, 0x16, 0x2c,
	0xab, 0xb7, 0xf0, 0xfd, 0xfe, 0x7d, 0xf3, 0x9b, 0x0f, 0x1e, 0x59, 0x3e, 0x53, 0x52, 0xd3, 0x69,
	0x4c, 0x95, 0x88, 0xd9, 0x54, 0xce, 0xf3, 0x98, 0x32, 0x26, 0xe7, 0x85, 0x8d, 0x17, 0x83, 0x78,
	0xc6, 0x8d, 0xa1, 0x97, 0x9c, 0x28, 0x2d, 0xad, 0x44, 0x0f, 0x1a, 0x32, 0xa1, 0x4a, 0x10, 0x47,
	0x26, 0x9e, 0x4c, 0x16, 0x83, 0x7b, 0xc7, 0x5b, 0xbc, 0x34, 0x37, 0x72, 0xae, 0x19, 0xff, 0xcb,
	0xac, 0x77, 0x0a, 0xdb, 0xe7, 0xdc, 0x6a, 0xc1, 0xcc, 0x58, 0x71, 0x86, 0x8e, 0x21, 0xa2, 0x8c,
	0x71, 0x65, 0x79, 0x9e, 0xb1, 0xa9, 0xe0, 0x85, 0xcd, 0x18, 0x8d, 0xc2, 0x2e, 0xe8, 0x1f, 0xa4,
	0x9d, 0x06, 0x19, 0x39, 0x60, 0x44, 0x7b, 0x63, 0xd8, 0x1e, 0xd6, 0xc1, 0x4e, 0xfc, 0x0a, 0xb6,
	0x66, 0xb5, 0x57, 0x04, 0xba, 0xa0, 0xdf, 0x3e, 0x79, 0x4a, 0x6e, 0x5d, 0x95, 0x6c, 0x24, 0xa7,
	0x8d, 0xb4, 0x77, 0x1f, 0xb6, 0xfc, 0x1c, 0x75, 0xe0, 0xce, 0x5c, 0x0b, 0x67, 0x76, 0x27, 0xad,
	0x9e, 0xbd, 0xaf, 0x21, 0x6c, 0xf9, 0x48, 0x74, 0x08, 0x43, 0x91, 0x7b, 0x30, 0x14, 0x39, 0x7a,
	0x01, 0x77, 0x8d, 0xe2, 0xcc, 0x6d, 0xfb, 0xef, 0xec, 0x8d, 0xc5, 0x53, 0xa7, 0x43, 0x4f, 0x60,
	0xa7, 0xe9, 0x29, 0x5b, 0x70, 0x6d, 0x84, 0x2c, 0xa2, 0x1d, 0xe7, 0x7e, 0xb7, 0x99, 0x4f, 0xea,
	0x31, 0x1a, 0xc1, 0x3d, 0x63, 0xa9, 0xe5, 0xd1, 0x6e, 0x17, 0xf4, 0x0f, 0x4f, 0x9e, 0x6d, 0xcb,
	0x6a, 0x34, 0x55, 0x58, 0xea, 0xdf, 0xe3, 0x4a, 0x94, 0xd6, 0x5a, 0xd7, 0xb5, 0xf9, 0x50, 0xb0,
	0x4c, 0x2a, 0xae, 0xa9, 0x15, 0xb2, 0xc8, 0x44, 0x1e, 0xed, 0xb9, 0xc4, 0x8e, 0x43, 0xde, 0x34,
	0xc0, 0xeb, 0x1c, 0xbd, 0xbc, 0x29, 0x77, 0xdf, 0x7d, 0xe0, 0xe3, 0xff, 0x2b, 0xf7, 0x4f, 0xb1,
	0x67, 0xdf, 0xc1, 0x72, 0x85, 0x83, 0xab, 0x15, 0x0e, 0xae, 0x57, 0x18, 0x7c, 0x2c, 0x31, 0xf8,
	0x5c, 0x62, 0xf0, 0xad, 0xc4, 0x60, 0x59, 0x62, 0xf0, 0xa3, 0xc4, 0xe0, 0x67, 0x89, 0x83, 0xeb,
	0x12, 0x83, 0x4f, 0x6b, 0x1c, 0x2c, 0xd7, 0x38, 0xb8, 0x5a, 0xe3, 0x00, 0x76, 0x85, 0xbc, 0x3d,
	0xe9, 0xec, 0xe0, 0xbc, 0x3e, 0xa9, 0x8b, 0xea, 0xa2, 0x2e, 0xc0, 0xbb, 0xa3, 0xcb, 0x0d, 0x85,
	0x90, 0x5b, 0x6f, 0xfa, 0xd4, 0x3f, 0xbf, 0x84, 0x0f, 0xdf, 0x7a, 0xaa, 0x90, 0x64, 0xa8, 0x04,
	0x19, 0x39, 0x7b, 0xff, 0x7b, 0xc8, 0x64, 0xf0, 0x2b, 0x7c, 0x74, 0xc3, 0x48, 0x92, 0xa1, 0x12,
	0x49, 0xe2, 0x38, 0x49, 0xe2, 0x49, 0x49, 0x32, 0x19, 0xbc, 0xdf, 0x77, 0xf7, 0xfc, 0xfc, 0x77,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xef, 0xeb, 0xe5, 0xae, 0x4b, 0x03, 0x00, 0x00,
}

func (this *MetricsSpec) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*MetricsSpec)
	if !ok {
		that2, ok := that.(MetricsSpec)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.AcceptedClientCa, that1.AcceptedClientCa) {
		return false
	}
	return true
}
func (this *AccountSpec) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AccountSpec)
	if !ok {
		that2, ok := that.(AccountSpec)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !this.Metrics.Equal(that1.Metrics) {
		return false
	}
	return true
}
func (this *Metrics) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Metrics)
	if !ok {
		that2, ok := that.(Metrics)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Uri != that1.Uri {
		return false
	}
	return true
}
func (this *Account) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Account)
	if !ok {
		that2, ok := that.(Account)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Id != that1.Id {
		return false
	}
	if !this.Spec.Equal(that1.Spec) {
		return false
	}
	if this.ResourceVersion != that1.ResourceVersion {
		return false
	}
	if this.State != that1.State {
		return false
	}
	if this.AsyncOperationId != that1.AsyncOperationId {
		return false
	}
	if !this.Metrics.Equal(that1.Metrics) {
		return false
	}
	return true
}
func (this *MetricsSpec) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&account.MetricsSpec{")
	s = append(s, "AcceptedClientCa: "+fmt.Sprintf("%#v", this.AcceptedClientCa)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *AccountSpec) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&account.AccountSpec{")
	if this.Metrics != nil {
		s = append(s, "Metrics: "+fmt.Sprintf("%#v", this.Metrics)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *Metrics) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&account.Metrics{")
	s = append(s, "Uri: "+fmt.Sprintf("%#v", this.Uri)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *Account) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 10)
	s = append(s, "&account.Account{")
	s = append(s, "Id: "+fmt.Sprintf("%#v", this.Id)+",\n")
	if this.Spec != nil {
		s = append(s, "Spec: "+fmt.Sprintf("%#v", this.Spec)+",\n")
	}
	s = append(s, "ResourceVersion: "+fmt.Sprintf("%#v", this.ResourceVersion)+",\n")
	s = append(s, "State: "+fmt.Sprintf("%#v", this.State)+",\n")
	s = append(s, "AsyncOperationId: "+fmt.Sprintf("%#v", this.AsyncOperationId)+",\n")
	if this.Metrics != nil {
		s = append(s, "Metrics: "+fmt.Sprintf("%#v", this.Metrics)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringMessage(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}
func (m *MetricsSpec) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MetricsSpec) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MetricsSpec) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.AcceptedClientCa) > 0 {
		i -= len(m.AcceptedClientCa)
		copy(dAtA[i:], m.AcceptedClientCa)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.AcceptedClientCa)))
		i--
		dAtA[i] = 0x12
	}
	return len(dAtA) - i, nil
}

func (m *AccountSpec) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AccountSpec) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AccountSpec) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Metrics != nil {
		{
			size, err := m.Metrics.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Metrics) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Metrics) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Metrics) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Uri) > 0 {
		i -= len(m.Uri)
		copy(dAtA[i:], m.Uri)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.Uri)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Account) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Account) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Account) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Metrics != nil {
		{
			size, err := m.Metrics.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x32
	}
	if len(m.AsyncOperationId) > 0 {
		i -= len(m.AsyncOperationId)
		copy(dAtA[i:], m.AsyncOperationId)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.AsyncOperationId)))
		i--
		dAtA[i] = 0x2a
	}
	if m.State != 0 {
		i = encodeVarintMessage(dAtA, i, uint64(m.State))
		i--
		dAtA[i] = 0x20
	}
	if len(m.ResourceVersion) > 0 {
		i -= len(m.ResourceVersion)
		copy(dAtA[i:], m.ResourceVersion)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.ResourceVersion)))
		i--
		dAtA[i] = 0x1a
	}
	if m.Spec != nil {
		{
			size, err := m.Spec.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintMessage(dAtA []byte, offset int, v uint64) int {
	offset -= sovMessage(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *MetricsSpec) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.AcceptedClientCa)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func (m *AccountSpec) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Metrics != nil {
		l = m.Metrics.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func (m *Metrics) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Uri)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func (m *Account) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.Spec != nil {
		l = m.Spec.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.ResourceVersion)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.State != 0 {
		n += 1 + sovMessage(uint64(m.State))
	}
	l = len(m.AsyncOperationId)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.Metrics != nil {
		l = m.Metrics.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func sovMessage(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMessage(x uint64) (n int) {
	return sovMessage(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *MetricsSpec) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&MetricsSpec{`,
		`AcceptedClientCa:` + fmt.Sprintf("%v", this.AcceptedClientCa) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AccountSpec) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AccountSpec{`,
		`Metrics:` + strings.Replace(this.Metrics.String(), "MetricsSpec", "MetricsSpec", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Metrics) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Metrics{`,
		`Uri:` + fmt.Sprintf("%v", this.Uri) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Account) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Account{`,
		`Id:` + fmt.Sprintf("%v", this.Id) + `,`,
		`Spec:` + strings.Replace(this.Spec.String(), "AccountSpec", "AccountSpec", 1) + `,`,
		`ResourceVersion:` + fmt.Sprintf("%v", this.ResourceVersion) + `,`,
		`State:` + fmt.Sprintf("%v", this.State) + `,`,
		`AsyncOperationId:` + fmt.Sprintf("%v", this.AsyncOperationId) + `,`,
		`Metrics:` + strings.Replace(this.Metrics.String(), "Metrics", "Metrics", 1) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringMessage(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *MetricsSpec) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MetricsSpec: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MetricsSpec: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AcceptedClientCa", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AcceptedClientCa = append(m.AcceptedClientCa[:0], dAtA[iNdEx:postIndex]...)
			if m.AcceptedClientCa == nil {
				m.AcceptedClientCa = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AccountSpec) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AccountSpec: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AccountSpec: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metrics", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Metrics == nil {
				m.Metrics = &MetricsSpec{}
			}
			if err := m.Metrics.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Metrics) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Metrics: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Metrics: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Uri", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Uri = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Account) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Account: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Account: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Spec", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Spec == nil {
				m.Spec = &AccountSpec{}
			}
			if err := m.Spec.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ResourceVersion", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ResourceVersion = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field State", wireType)
			}
			m.State = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.State |= v1.ResourceState(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AsyncOperationId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AsyncOperationId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metrics", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Metrics == nil {
				m.Metrics = &Metrics{}
			}
			if err := m.Metrics.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMessage(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMessage
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMessage
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMessage
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMessage        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMessage          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMessage = fmt.Errorf("proto: unexpected end of group")
)
