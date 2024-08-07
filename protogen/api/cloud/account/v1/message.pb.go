// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: temporal/api/cloud/account/v1/message.proto

package account

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
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
	// Enables the endpoint from which clients can scrape all their namespace metrics.
	Enabled bool `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	// The base64 encoded ca cert(s) in PEM format that clients connecting to the metrics endpoint can use for authentication.
	// This must only be one value, but the CA can have a chain.
	AcceptedClientCa string `protobuf:"bytes,2,opt,name=accepted_client_ca,json=acceptedClientCa,proto3" json:"accepted_client_ca,omitempty"`
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

func (m *MetricsSpec) GetEnabled() bool {
	if m != nil {
		return m.Enabled
	}
	return false
}

func (m *MetricsSpec) GetAcceptedClientCa() string {
	if m != nil {
		return m.AcceptedClientCa
	}
	return ""
}

type AccountSpec struct {
	// The metrics specification for this account.
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
	// The account specification.
	Spec *AccountSpec `protobuf:"bytes,1,opt,name=spec,proto3" json:"spec,omitempty"`
	// The current version of the account specification.
	// The next update operation will have to include this version.
	ResourceVersion string `protobuf:"bytes,2,opt,name=resource_version,json=resourceVersion,proto3" json:"resource_version,omitempty"`
	// The current state of the account.
	// Possible values: activating, activationfailed, active, updating, updatefailed, deleting, deletefailed, deleted, suspending, suspendfailed, suspended.
	// For any failed state, reach out to Temporal Cloud support for remediation.
	State string `protobuf:"bytes,3,opt,name=state,proto3" json:"state,omitempty"`
	// The id of the async operation that is updating the account, if any.
	AsyncOperationId string `protobuf:"bytes,4,opt,name=async_operation_id,json=asyncOperationId,proto3" json:"async_operation_id,omitempty"`
	// Information related to metrics.
	Metrics *Metrics `protobuf:"bytes,5,opt,name=metrics,proto3" json:"metrics,omitempty"`
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

func (m *Account) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
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
	// 381 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0xb1, 0xae, 0xd3, 0x30,
	0x14, 0x8d, 0x69, 0x4b, 0xa8, 0x3b, 0x50, 0x59, 0x0c, 0x91, 0x10, 0x56, 0x95, 0x01, 0x15, 0x8a,
	0x12, 0x15, 0x46, 0x24, 0x04, 0x94, 0x85, 0x01, 0x21, 0xa5, 0x82, 0x81, 0x25, 0x72, 0x9d, 0xab,
	0xca, 0x52, 0x1a, 0x5b, 0xb6, 0x53, 0x89, 0x8d, 0x4f, 0xe0, 0x33, 0xf8, 0x14, 0xc6, 0x8e, 0x1d,
	0x5f, 0xd3, 0xe5, 0x8d, 0x9d, 0xdf, 0xf4, 0x54, 0x27, 0x79, 0xed, 0xf0, 0xf4, 0xd4, 0xcd, 0xf7,
	0x9e, 0x7b, 0xcf, 0x39, 0x3e, 0xba, 0x78, 0x62, 0x61, 0xa5, 0xa4, 0x66, 0x79, 0xcc, 0x94, 0x88,
	0x79, 0x2e, 0xcb, 0x2c, 0x66, 0x9c, 0xcb, 0xb2, 0xb0, 0xf1, 0x7a, 0x1a, 0xaf, 0xc0, 0x18, 0xb6,
	0x84, 0x48, 0x69, 0x69, 0x25, 0x79, 0xd1, 0x0e, 0x47, 0x4c, 0x89, 0xc8, 0x0d, 0x47, 0xcd, 0x70,
	0xb4, 0x9e, 0x86, 0x3f, 0xf0, 0xe0, 0x1b, 0x58, 0x2d, 0xb8, 0x99, 0x2b, 0xe0, 0x24, 0xc0, 0x3e,
	0x14, 0x6c, 0x91, 0x43, 0x16, 0xa0, 0x11, 0x1a, 0x3f, 0x49, 0xda, 0x92, 0xbc, 0xc1, 0x84, 0x71,
	0x0e, 0xca, 0x42, 0x96, 0xf2, 0x5c, 0x40, 0x61, 0x53, 0xce, 0x82, 0x47, 0x23, 0x34, 0xee, 0x27,
	0xc3, 0x16, 0x99, 0x39, 0x60, 0xc6, 0xc2, 0x39, 0x1e, 0x7c, 0xaa, 0x45, 0x1c, 0xed, 0x17, 0xec,
	0xaf, 0x6a, 0x15, 0x47, 0x3b, 0x78, 0xfb, 0x3a, 0x7a, 0xd0, 0x56, 0x74, 0xe6, 0x29, 0x69, 0x57,
	0xc3, 0xe7, 0xd8, 0x6f, 0xfa, 0x64, 0x88, 0x3b, 0xa5, 0x16, 0x8e, 0xac, 0x9f, 0x1c, 0x9f, 0xe1,
	0x0d, 0xc2, 0x7e, 0x23, 0x49, 0x3e, 0xe0, 0xae, 0x51, 0xc0, 0x2f, 0xd4, 0x3a, 0x33, 0x9a, 0xb8,
	0x3d, 0xf2, 0x0a, 0x0f, 0x35, 0x18, 0x59, 0x6a, 0x0e, 0xe9, 0x1a, 0xb4, 0x11, 0xb2, 0x68, 0x7e,
	0xfa, 0xb4, 0xed, 0xff, 0xac, 0xdb, 0xe4, 0x19, 0xee, 0x19, 0xcb, 0x2c, 0x04, 0x1d, 0x87, 0xd7,
	0x85, 0x0b, 0xcb, 0xfc, 0x2e, 0x78, 0x2a, 0x15, 0x68, 0x66, 0x85, 0x2c, 0x52, 0x91, 0x05, 0xdd,
	0x26, 0xac, 0x23, 0xf2, 0xbd, 0x05, 0xbe, 0x66, 0xe4, 0xe3, 0x29, 0x9d, 0x9e, 0x73, 0xfc, 0xf2,
	0xb2, 0x74, 0xee, 0x92, 0xf9, 0xcc, 0x36, 0x3b, 0xea, 0x6d, 0x77, 0xd4, 0x3b, 0xec, 0x28, 0xfa,
	0x53, 0x51, 0xf4, 0xaf, 0xa2, 0xe8, 0x7f, 0x45, 0xd1, 0xa6, 0xa2, 0xe8, 0xaa, 0xa2, 0xe8, 0xba,
	0xa2, 0xde, 0xa1, 0xa2, 0xe8, 0xef, 0x9e, 0x7a, 0x9b, 0x3d, 0xf5, 0xb6, 0x7b, 0xea, 0xfd, 0x9a,
	0x2c, 0xe5, 0x49, 0x48, 0xc8, 0x7b, 0xaf, 0xe9, 0x7d, 0xf3, 0x5c, 0x3c, 0x76, 0xe7, 0xf4, 0xee,
	0x36, 0x00, 0x00, 0xff, 0xff, 0xb4, 0x46, 0xde, 0xa5, 0x7d, 0x02, 0x00, 0x00,
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
	if this.Enabled != that1.Enabled {
		return false
	}
	if this.AcceptedClientCa != that1.AcceptedClientCa {
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
	s := make([]string, 0, 6)
	s = append(s, "&account.MetricsSpec{")
	s = append(s, "Enabled: "+fmt.Sprintf("%#v", this.Enabled)+",\n")
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
	s := make([]string, 0, 9)
	s = append(s, "&account.Account{")
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
	if m.Enabled {
		i--
		if m.Enabled {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x8
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
		dAtA[i] = 0x2a
	}
	if len(m.AsyncOperationId) > 0 {
		i -= len(m.AsyncOperationId)
		copy(dAtA[i:], m.AsyncOperationId)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.AsyncOperationId)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.State) > 0 {
		i -= len(m.State)
		copy(dAtA[i:], m.State)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.State)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.ResourceVersion) > 0 {
		i -= len(m.ResourceVersion)
		copy(dAtA[i:], m.ResourceVersion)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.ResourceVersion)))
		i--
		dAtA[i] = 0x12
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
	if m.Enabled {
		n += 2
	}
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
	if m.Spec != nil {
		l = m.Spec.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.ResourceVersion)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.State)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
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
		`Enabled:` + fmt.Sprintf("%v", this.Enabled) + `,`,
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
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Enabled", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Enabled = bool(v != 0)
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AcceptedClientCa", wireType)
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
			m.AcceptedClientCa = string(dAtA[iNdEx:postIndex])
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
		case 2:
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
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field State", wireType)
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
			m.State = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
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
		case 5:
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
