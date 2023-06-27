// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: services/saasapi/operator/request/v1/message.proto

package request

import (
	bytes "bytes"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	types "github.com/gogo/protobuf/types"
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

type RequestStatus struct {
	// id of the request
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// the root account id
	Account string `protobuf:"bytes,2,opt,name=account,proto3" json:"account,omitempty"`
	// the resource type, e.g. account, namespace etc
	ResourceType string `protobuf:"bytes,3,opt,name=resource_type,json=resourceType,proto3" json:"resource_type,omitempty"`
	// the resource id, if any
	ResourceId string `protobuf:"bytes,4,opt,name=resource_id,json=resourceId,proto3" json:"resource_id,omitempty"`
	// the operation type
	OperationType string `protobuf:"bytes,5,opt,name=operation_type,json=operationType,proto3" json:"operation_type,omitempty"`
	// the state of the request
	State string `protobuf:"bytes,6,opt,name=state,proto3" json:"state,omitempty"`
	// the recommended next check duration
	CheckDuration *types.Duration `protobuf:"bytes,7,opt,name=check_duration,json=checkDuration,proto3" json:"check_duration,omitempty"`
	// the failure reason, if any
	FailureReason string `protobuf:"bytes,8,opt,name=failure_reason,json=failureReason,proto3" json:"failure_reason,omitempty"`
	// the result of the request, if any
	Result []byte `protobuf:"bytes,9,opt,name=result,proto3" json:"result,omitempty"`
	// the time when the request started
	StartTime *types.Timestamp `protobuf:"bytes,10,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	// the time when the request finished
	FinishTime *types.Timestamp `protobuf:"bytes,11,opt,name=finish_time,json=finishTime,proto3" json:"finish_time,omitempty"`
	// the workflow id
	WorkflowId string `protobuf:"bytes,12,opt,name=workflow_id,json=workflowId,proto3" json:"workflow_id,omitempty"`
	// the workflow run id
	WorkflowRunId string `protobuf:"bytes,13,opt,name=workflow_run_id,json=workflowRunId,proto3" json:"workflow_run_id,omitempty"`
	// the workflow status
	WorkflowStatus string `protobuf:"bytes,14,opt,name=workflow_status,json=workflowStatus,proto3" json:"workflow_status,omitempty"`
}

func (m *RequestStatus) Reset()      { *m = RequestStatus{} }
func (*RequestStatus) ProtoMessage() {}
func (*RequestStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_6cbc42ba3676112f, []int{0}
}
func (m *RequestStatus) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *RequestStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_RequestStatus.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *RequestStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RequestStatus.Merge(m, src)
}
func (m *RequestStatus) XXX_Size() int {
	return m.Size()
}
func (m *RequestStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_RequestStatus.DiscardUnknown(m)
}

var xxx_messageInfo_RequestStatus proto.InternalMessageInfo

func (m *RequestStatus) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *RequestStatus) GetAccount() string {
	if m != nil {
		return m.Account
	}
	return ""
}

func (m *RequestStatus) GetResourceType() string {
	if m != nil {
		return m.ResourceType
	}
	return ""
}

func (m *RequestStatus) GetResourceId() string {
	if m != nil {
		return m.ResourceId
	}
	return ""
}

func (m *RequestStatus) GetOperationType() string {
	if m != nil {
		return m.OperationType
	}
	return ""
}

func (m *RequestStatus) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

func (m *RequestStatus) GetCheckDuration() *types.Duration {
	if m != nil {
		return m.CheckDuration
	}
	return nil
}

func (m *RequestStatus) GetFailureReason() string {
	if m != nil {
		return m.FailureReason
	}
	return ""
}

func (m *RequestStatus) GetResult() []byte {
	if m != nil {
		return m.Result
	}
	return nil
}

func (m *RequestStatus) GetStartTime() *types.Timestamp {
	if m != nil {
		return m.StartTime
	}
	return nil
}

func (m *RequestStatus) GetFinishTime() *types.Timestamp {
	if m != nil {
		return m.FinishTime
	}
	return nil
}

func (m *RequestStatus) GetWorkflowId() string {
	if m != nil {
		return m.WorkflowId
	}
	return ""
}

func (m *RequestStatus) GetWorkflowRunId() string {
	if m != nil {
		return m.WorkflowRunId
	}
	return ""
}

func (m *RequestStatus) GetWorkflowStatus() string {
	if m != nil {
		return m.WorkflowStatus
	}
	return ""
}

func init() {
	proto.RegisterType((*RequestStatus)(nil), "services.saasapi.operator.request.v1.RequestStatus")
}

func init() {
	proto.RegisterFile("services/saasapi/operator/request/v1/message.proto", fileDescriptor_6cbc42ba3676112f)
}

var fileDescriptor_6cbc42ba3676112f = []byte{
	// 483 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x93, 0xbd, 0x8e, 0xd3, 0x40,
	0x14, 0x85, 0x3d, 0x61, 0x37, 0x4b, 0xc6, 0xb1, 0x91, 0x46, 0x08, 0x0d, 0x29, 0x26, 0x11, 0xbf,
	0xa9, 0x6c, 0xed, 0xd2, 0x80, 0xb6, 0x41, 0x88, 0x26, 0xad, 0xd9, 0x8a, 0x26, 0x9a, 0xb5, 0x27,
	0xd9, 0xd1, 0x3a, 0x1e, 0x33, 0x3f, 0x59, 0x6d, 0xc7, 0x23, 0xf0, 0x16, 0xf0, 0x28, 0x94, 0x29,
	0xb7, 0x24, 0x4e, 0x43, 0x99, 0x47, 0x40, 0x9e, 0xf1, 0x44, 0x08, 0x0a, 0xe8, 0x7c, 0xcf, 0xfd,
	0xce, 0xbd, 0xba, 0x47, 0x63, 0x78, 0xa6, 0x98, 0x5c, 0xf3, 0x9c, 0xa9, 0x54, 0x51, 0xaa, 0x68,
	0xcd, 0x53, 0x51, 0x33, 0x49, 0xb5, 0x90, 0xa9, 0x64, 0x9f, 0x0c, 0x53, 0x3a, 0x5d, 0x9f, 0xa6,
	0x2b, 0xa6, 0x14, 0x5d, 0xb2, 0xa4, 0x96, 0x42, 0x0b, 0xf4, 0xcc, 0x7b, 0x92, 0xce, 0x93, 0x78,
	0x4f, 0xd2, 0x79, 0x92, 0xf5, 0xe9, 0x88, 0x2c, 0x85, 0x58, 0x96, 0x2c, 0xb5, 0x9e, 0x4b, 0xb3,
	0x48, 0x0b, 0x23, 0xa9, 0xe6, 0xa2, 0x72, 0x53, 0x46, 0xe3, 0x3f, 0xfb, 0x9a, 0xaf, 0x98, 0xd2,
	0x74, 0x55, 0x3b, 0xe0, 0xc9, 0xd7, 0x23, 0x18, 0x65, 0x6e, 0xde, 0x07, 0x4d, 0xb5, 0x51, 0x28,
	0x86, 0x3d, 0x5e, 0x60, 0x30, 0x01, 0xd3, 0x41, 0xd6, 0xe3, 0x05, 0xc2, 0xf0, 0x84, 0xe6, 0xb9,
	0x30, 0x95, 0xc6, 0x3d, 0x2b, 0xfa, 0x12, 0x3d, 0x85, 0x91, 0x64, 0x4a, 0x18, 0x99, 0xb3, 0xb9,
	0xbe, 0xad, 0x19, 0xbe, 0x67, 0xfb, 0x43, 0x2f, 0x5e, 0xdc, 0xd6, 0x0c, 0x8d, 0x61, 0x78, 0x80,
	0x78, 0x81, 0x8f, 0x2c, 0x02, 0xbd, 0x34, 0x2b, 0xd0, 0x73, 0x18, 0xbb, 0xcb, 0xb8, 0xa8, 0xdc,
	0x98, 0x63, 0xcb, 0x44, 0x07, 0xd5, 0xce, 0x79, 0x08, 0x8f, 0x95, 0xa6, 0x9a, 0xe1, 0xbe, 0xed,
	0xba, 0x02, 0xbd, 0x85, 0x71, 0x7e, 0xc5, 0xf2, 0xeb, 0xb9, 0xbf, 0x1b, 0x9f, 0x4c, 0xc0, 0x34,
	0x3c, 0x7b, 0x9c, 0xb8, 0xc3, 0x13, 0x7f, 0x78, 0xf2, 0xbe, 0x03, 0xb2, 0xc8, 0x1a, 0x7c, 0xd9,
	0xae, 0x5f, 0x50, 0x5e, 0x1a, 0xc9, 0xe6, 0x92, 0x51, 0x25, 0x2a, 0x7c, 0xdf, 0xad, 0xef, 0xd4,
	0xcc, 0x8a, 0xe8, 0x11, 0xec, 0x4b, 0xa6, 0x4c, 0xa9, 0xf1, 0x60, 0x02, 0xa6, 0xc3, 0xac, 0xab,
	0xd0, 0x1b, 0x08, 0x95, 0xa6, 0x52, 0xcf, 0xdb, 0x60, 0x31, 0xb4, 0xcb, 0x47, 0x7f, 0x2d, 0xbf,
	0xf0, 0xa9, 0x67, 0x03, 0x4b, 0xb7, 0x35, 0x3a, 0x87, 0xe1, 0x82, 0x57, 0x5c, 0x5d, 0x39, 0x6f,
	0xf8, 0x4f, 0x2f, 0x74, 0xb8, 0x35, 0x8f, 0x61, 0x78, 0x23, 0xe4, 0xf5, 0xa2, 0x14, 0x37, 0x6d,
	0xac, 0x43, 0x17, 0xab, 0x97, 0x66, 0x05, 0x7a, 0x01, 0x1f, 0x1c, 0x00, 0x69, 0xaa, 0x16, 0x8a,
	0xdc, 0x61, 0x5e, 0xce, 0x4c, 0x35, 0x2b, 0xd0, 0xcb, 0xdf, 0x38, 0x65, 0x5f, 0x00, 0x8e, 0x2d,
	0x17, 0x7b, 0xd9, 0xbd, 0x8b, 0x77, 0xd5, 0x66, 0x4b, 0x82, 0xbb, 0x2d, 0x09, 0xf6, 0x5b, 0x02,
	0x3e, 0x37, 0x04, 0x7c, 0x6b, 0x08, 0xf8, 0xde, 0x10, 0xb0, 0x69, 0x08, 0xf8, 0xd1, 0x10, 0xf0,
	0xb3, 0x21, 0xc1, 0xbe, 0x21, 0xe0, 0xcb, 0x8e, 0x04, 0x9b, 0x1d, 0x09, 0xee, 0x76, 0x24, 0xf8,
	0xf8, 0x5a, 0xaf, 0x6a, 0x59, 0x26, 0x79, 0x29, 0x4c, 0x91, 0xfe, 0xcf, 0x6f, 0x70, 0xde, 0x7d,
	0x5e, 0xf6, 0x6d, 0x02, 0xaf, 0x7e, 0x05, 0x00, 0x00, 0xff, 0xff, 0x9f, 0xd5, 0xcb, 0x3d, 0x3d,
	0x03, 0x00, 0x00,
}

func (this *RequestStatus) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*RequestStatus)
	if !ok {
		that2, ok := that.(RequestStatus)
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
	if this.Account != that1.Account {
		return false
	}
	if this.ResourceType != that1.ResourceType {
		return false
	}
	if this.ResourceId != that1.ResourceId {
		return false
	}
	if this.OperationType != that1.OperationType {
		return false
	}
	if this.State != that1.State {
		return false
	}
	if !this.CheckDuration.Equal(that1.CheckDuration) {
		return false
	}
	if this.FailureReason != that1.FailureReason {
		return false
	}
	if !bytes.Equal(this.Result, that1.Result) {
		return false
	}
	if !this.StartTime.Equal(that1.StartTime) {
		return false
	}
	if !this.FinishTime.Equal(that1.FinishTime) {
		return false
	}
	if this.WorkflowId != that1.WorkflowId {
		return false
	}
	if this.WorkflowRunId != that1.WorkflowRunId {
		return false
	}
	if this.WorkflowStatus != that1.WorkflowStatus {
		return false
	}
	return true
}
func (this *RequestStatus) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 18)
	s = append(s, "&request.RequestStatus{")
	s = append(s, "Id: "+fmt.Sprintf("%#v", this.Id)+",\n")
	s = append(s, "Account: "+fmt.Sprintf("%#v", this.Account)+",\n")
	s = append(s, "ResourceType: "+fmt.Sprintf("%#v", this.ResourceType)+",\n")
	s = append(s, "ResourceId: "+fmt.Sprintf("%#v", this.ResourceId)+",\n")
	s = append(s, "OperationType: "+fmt.Sprintf("%#v", this.OperationType)+",\n")
	s = append(s, "State: "+fmt.Sprintf("%#v", this.State)+",\n")
	if this.CheckDuration != nil {
		s = append(s, "CheckDuration: "+fmt.Sprintf("%#v", this.CheckDuration)+",\n")
	}
	s = append(s, "FailureReason: "+fmt.Sprintf("%#v", this.FailureReason)+",\n")
	s = append(s, "Result: "+fmt.Sprintf("%#v", this.Result)+",\n")
	if this.StartTime != nil {
		s = append(s, "StartTime: "+fmt.Sprintf("%#v", this.StartTime)+",\n")
	}
	if this.FinishTime != nil {
		s = append(s, "FinishTime: "+fmt.Sprintf("%#v", this.FinishTime)+",\n")
	}
	s = append(s, "WorkflowId: "+fmt.Sprintf("%#v", this.WorkflowId)+",\n")
	s = append(s, "WorkflowRunId: "+fmt.Sprintf("%#v", this.WorkflowRunId)+",\n")
	s = append(s, "WorkflowStatus: "+fmt.Sprintf("%#v", this.WorkflowStatus)+",\n")
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
func (m *RequestStatus) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RequestStatus) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *RequestStatus) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.WorkflowStatus) > 0 {
		i -= len(m.WorkflowStatus)
		copy(dAtA[i:], m.WorkflowStatus)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.WorkflowStatus)))
		i--
		dAtA[i] = 0x72
	}
	if len(m.WorkflowRunId) > 0 {
		i -= len(m.WorkflowRunId)
		copy(dAtA[i:], m.WorkflowRunId)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.WorkflowRunId)))
		i--
		dAtA[i] = 0x6a
	}
	if len(m.WorkflowId) > 0 {
		i -= len(m.WorkflowId)
		copy(dAtA[i:], m.WorkflowId)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.WorkflowId)))
		i--
		dAtA[i] = 0x62
	}
	if m.FinishTime != nil {
		{
			size, err := m.FinishTime.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x5a
	}
	if m.StartTime != nil {
		{
			size, err := m.StartTime.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x52
	}
	if len(m.Result) > 0 {
		i -= len(m.Result)
		copy(dAtA[i:], m.Result)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.Result)))
		i--
		dAtA[i] = 0x4a
	}
	if len(m.FailureReason) > 0 {
		i -= len(m.FailureReason)
		copy(dAtA[i:], m.FailureReason)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.FailureReason)))
		i--
		dAtA[i] = 0x42
	}
	if m.CheckDuration != nil {
		{
			size, err := m.CheckDuration.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x3a
	}
	if len(m.State) > 0 {
		i -= len(m.State)
		copy(dAtA[i:], m.State)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.State)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.OperationType) > 0 {
		i -= len(m.OperationType)
		copy(dAtA[i:], m.OperationType)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.OperationType)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.ResourceId) > 0 {
		i -= len(m.ResourceId)
		copy(dAtA[i:], m.ResourceId)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.ResourceId)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.ResourceType) > 0 {
		i -= len(m.ResourceType)
		copy(dAtA[i:], m.ResourceType)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.ResourceType)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Account) > 0 {
		i -= len(m.Account)
		copy(dAtA[i:], m.Account)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.Account)))
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
func (m *RequestStatus) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.Account)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.ResourceType)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.ResourceId)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.OperationType)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.State)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.CheckDuration != nil {
		l = m.CheckDuration.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.FailureReason)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.Result)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.StartTime != nil {
		l = m.StartTime.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.FinishTime != nil {
		l = m.FinishTime.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.WorkflowId)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.WorkflowRunId)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.WorkflowStatus)
	if l > 0 {
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
func (this *RequestStatus) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&RequestStatus{`,
		`Id:` + fmt.Sprintf("%v", this.Id) + `,`,
		`Account:` + fmt.Sprintf("%v", this.Account) + `,`,
		`ResourceType:` + fmt.Sprintf("%v", this.ResourceType) + `,`,
		`ResourceId:` + fmt.Sprintf("%v", this.ResourceId) + `,`,
		`OperationType:` + fmt.Sprintf("%v", this.OperationType) + `,`,
		`State:` + fmt.Sprintf("%v", this.State) + `,`,
		`CheckDuration:` + strings.Replace(fmt.Sprintf("%v", this.CheckDuration), "Duration", "types.Duration", 1) + `,`,
		`FailureReason:` + fmt.Sprintf("%v", this.FailureReason) + `,`,
		`Result:` + fmt.Sprintf("%v", this.Result) + `,`,
		`StartTime:` + strings.Replace(fmt.Sprintf("%v", this.StartTime), "Timestamp", "types.Timestamp", 1) + `,`,
		`FinishTime:` + strings.Replace(fmt.Sprintf("%v", this.FinishTime), "Timestamp", "types.Timestamp", 1) + `,`,
		`WorkflowId:` + fmt.Sprintf("%v", this.WorkflowId) + `,`,
		`WorkflowRunId:` + fmt.Sprintf("%v", this.WorkflowRunId) + `,`,
		`WorkflowStatus:` + fmt.Sprintf("%v", this.WorkflowStatus) + `,`,
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
func (m *RequestStatus) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: RequestStatus: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: RequestStatus: illegal tag %d (wire type %d)", fieldNum, wire)
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
				return fmt.Errorf("proto: wrong wireType = %d for field Account", wireType)
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
			m.Account = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ResourceType", wireType)
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
			m.ResourceType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ResourceId", wireType)
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
			m.ResourceId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field OperationType", wireType)
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
			m.OperationType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
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
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CheckDuration", wireType)
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
			if m.CheckDuration == nil {
				m.CheckDuration = &types.Duration{}
			}
			if err := m.CheckDuration.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FailureReason", wireType)
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
			m.FailureReason = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 9:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Result", wireType)
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
			m.Result = append(m.Result[:0], dAtA[iNdEx:postIndex]...)
			if m.Result == nil {
				m.Result = []byte{}
			}
			iNdEx = postIndex
		case 10:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StartTime", wireType)
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
			if m.StartTime == nil {
				m.StartTime = &types.Timestamp{}
			}
			if err := m.StartTime.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 11:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FinishTime", wireType)
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
			if m.FinishTime == nil {
				m.FinishTime = &types.Timestamp{}
			}
			if err := m.FinishTime.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 12:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field WorkflowId", wireType)
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
			m.WorkflowId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 13:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field WorkflowRunId", wireType)
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
			m.WorkflowRunId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 14:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field WorkflowStatus", wireType)
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
			m.WorkflowStatus = string(dAtA[iNdEx:postIndex])
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