// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/request/v1/message.proto

package request

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	types "github.com/gogo/protobuf/types"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strconv "strconv"
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

type State int32

const (
	STATE_UNSPECIFIED State = 0
	STATE_PENDING     State = 1
	STATE_IN_PROGRESS State = 2
	STATE_FAILED      State = 3
	STATE_CANCELLED   State = 4
	STATE_FULFILLED   State = 5
	STATE_REJECTED    State = 6
)

var State_name = map[int32]string{
	0: "Unspecified",
	1: "Pending",
	2: "InProgress",
	3: "Failed",
	4: "Cancelled",
	5: "Fulfilled",
	6: "Rejected",
}

var State_value = map[string]int32{
	"Unspecified": 0,
	"Pending":     1,
	"InProgress":  2,
	"Failed":      3,
	"Cancelled":   4,
	"Fulfilled":   5,
	"Rejected":    6,
}

func (State) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_78380c7344c0bbc3, []int{0}
}

type RequestStatus struct {
	// the request id
	RequestId string `protobuf:"bytes,2,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	// the current state of this request
	State State `protobuf:"varint,3,opt,name=state,proto3,enum=api.request.v1.State" json:"state,omitempty"`
	// the recommened duration to check back for an update in the request's status
	CheckDuration *types.Duration `protobuf:"bytes,4,opt,name=check_duration,json=checkDuration,proto3" json:"check_duration,omitempty"`
	// the operation being performed
	OperationType string `protobuf:"bytes,5,opt,name=operation_type,json=operationType,proto3" json:"operation_type,omitempty"`
	// the id of the resource on which the opeartion is being performed
	ResourceId string `protobuf:"bytes,6,opt,name=resource_id,json=resourceId,proto3" json:"resource_id,omitempty"`
	// the type of the resource
	ResourceType string `protobuf:"bytes,7,opt,name=resource_type,json=resourceType,proto3" json:"resource_type,omitempty"`
	// if the request failed, the reason for the failure
	FailureReason string `protobuf:"bytes,8,opt,name=failure_reason,json=failureReason,proto3" json:"failure_reason,omitempty"`
	// the date and time when the request initiated
	StartTime *types.Timestamp `protobuf:"bytes,9,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	// the date and time when the request completed
	FinishTime *types.Timestamp `protobuf:"bytes,10,opt,name=finish_time,json=finishTime,proto3" json:"finish_time,omitempty"`
}

func (m *RequestStatus) Reset()      { *m = RequestStatus{} }
func (*RequestStatus) ProtoMessage() {}
func (*RequestStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_78380c7344c0bbc3, []int{0}
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

func (m *RequestStatus) GetRequestId() string {
	if m != nil {
		return m.RequestId
	}
	return ""
}

func (m *RequestStatus) GetState() State {
	if m != nil {
		return m.State
	}
	return STATE_UNSPECIFIED
}

func (m *RequestStatus) GetCheckDuration() *types.Duration {
	if m != nil {
		return m.CheckDuration
	}
	return nil
}

func (m *RequestStatus) GetOperationType() string {
	if m != nil {
		return m.OperationType
	}
	return ""
}

func (m *RequestStatus) GetResourceId() string {
	if m != nil {
		return m.ResourceId
	}
	return ""
}

func (m *RequestStatus) GetResourceType() string {
	if m != nil {
		return m.ResourceType
	}
	return ""
}

func (m *RequestStatus) GetFailureReason() string {
	if m != nil {
		return m.FailureReason
	}
	return ""
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

func init() {
	proto.RegisterEnum("api.request.v1.State", State_name, State_value)
	proto.RegisterType((*RequestStatus)(nil), "api.request.v1.RequestStatus")
}

func init() { proto.RegisterFile("api/request/v1/message.proto", fileDescriptor_78380c7344c0bbc3) }

var fileDescriptor_78380c7344c0bbc3 = []byte{
	// 519 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xcf, 0x6e, 0xd3, 0x40,
	0x10, 0x87, 0xbd, 0xcd, 0x1f, 0x9a, 0x49, 0x63, 0xdc, 0x45, 0x95, 0x4c, 0x04, 0xdb, 0xa8, 0xa8,
	0x52, 0x04, 0x92, 0xad, 0x96, 0x13, 0xea, 0x85, 0x90, 0x38, 0x95, 0xab, 0x28, 0x44, 0x4e, 0x2a,
	0x21, 0x2e, 0x96, 0x9b, 0x6c, 0x52, 0x8b, 0x24, 0x36, 0xde, 0x75, 0xa5, 0xde, 0x78, 0x04, 0x8e,
	0x3c, 0x02, 0x37, 0x5e, 0x83, 0x63, 0x8e, 0x3d, 0x12, 0xe7, 0xc2, 0xb1, 0x8f, 0x80, 0xbc, 0x6b,
	0xb7, 0x2a, 0x1c, 0xb8, 0x79, 0xbf, 0xf9, 0x66, 0xf6, 0xb7, 0x23, 0xc3, 0x33, 0x2f, 0xf4, 0xcd,
	0x88, 0x7e, 0x8e, 0x29, 0xe3, 0xe6, 0xd5, 0x91, 0xb9, 0xa0, 0x8c, 0x79, 0x33, 0x6a, 0x84, 0x51,
	0xc0, 0x03, 0xac, 0x7a, 0xa1, 0x6f, 0x64, 0x55, 0xe3, 0xea, 0xa8, 0x4e, 0x66, 0x41, 0x30, 0x9b,
	0x53, 0x53, 0x54, 0x2f, 0xe2, 0xa9, 0x39, 0x89, 0x23, 0x8f, 0xfb, 0xc1, 0x52, 0xfa, 0xf5, 0xfd,
	0xbf, 0xeb, 0xdc, 0x5f, 0x50, 0xc6, 0xbd, 0x45, 0x28, 0x85, 0x83, 0x1f, 0x05, 0xa8, 0x39, 0x72,
	0xde, 0x90, 0x7b, 0x3c, 0x66, 0xf8, 0x39, 0x40, 0x76, 0x81, 0xeb, 0x4f, 0xf4, 0xad, 0x06, 0x6a,
	0x56, 0x9c, 0x4a, 0x46, 0xec, 0x09, 0x7e, 0x05, 0x25, 0xc6, 0x3d, 0x4e, 0xf5, 0x42, 0x03, 0x35,
	0xd5, 0xe3, 0x3d, 0xe3, 0x61, 0x22, 0x23, 0x9d, 0x42, 0x1d, 0xe9, 0xe0, 0xb7, 0xa0, 0x8e, 0x2f,
	0xe9, 0xf8, 0x93, 0x9b, 0xc7, 0xd2, 0x8b, 0x0d, 0xd4, 0xac, 0x1e, 0x3f, 0x35, 0x64, 0x2e, 0x23,
	0xcf, 0x65, 0x74, 0x32, 0xc1, 0xa9, 0x89, 0x86, 0xfc, 0x88, 0x0f, 0x41, 0x0d, 0x42, 0x2a, 0x0f,
	0x2e, 0xbf, 0x0e, 0xa9, 0x5e, 0x12, 0x89, 0x6a, 0x77, 0x74, 0x74, 0x1d, 0x52, 0xbc, 0x0f, 0xd5,
	0x88, 0xb2, 0x20, 0x8e, 0xc6, 0x34, 0x4d, 0x5d, 0x16, 0x0e, 0xe4, 0xc8, 0x9e, 0xe0, 0x17, 0x50,
	0xbb, 0x13, 0xc4, 0x98, 0x47, 0x42, 0xd9, 0xc9, 0xa1, 0x98, 0x72, 0x08, 0xea, 0xd4, 0xf3, 0xe7,
	0x71, 0x44, 0xdd, 0x88, 0x7a, 0x2c, 0x58, 0xea, 0xdb, 0xf2, 0xb2, 0x8c, 0x3a, 0x02, 0xe2, 0x37,
	0x00, 0x8c, 0x7b, 0x11, 0x77, 0xd3, 0x65, 0xea, 0x15, 0xf1, 0xa2, 0xfa, 0x3f, 0x2f, 0x1a, 0xe5,
	0x9b, 0x76, 0x2a, 0xc2, 0x4e, 0xcf, 0xf8, 0x04, 0xaa, 0x53, 0x7f, 0xe9, 0xb3, 0x4b, 0xd9, 0x0b,
	0xff, 0xed, 0x05, 0xa9, 0xa7, 0xe0, 0xac, 0xb8, 0x8d, 0xb4, 0xad, 0x97, 0xdf, 0x10, 0x94, 0xc4,
	0x92, 0xf1, 0x1e, 0xec, 0x0e, 0x47, 0xad, 0x91, 0xe5, 0x9e, 0xf7, 0x87, 0x03, 0xab, 0x6d, 0x77,
	0x6d, 0xab, 0xa3, 0x29, 0x78, 0x17, 0x6a, 0x12, 0x0f, 0xac, 0x7e, 0xc7, 0xee, 0x9f, 0x6a, 0xe8,
	0xde, 0xb4, 0xfb, 0xee, 0xc0, 0x79, 0x7f, 0xea, 0x58, 0xc3, 0xa1, 0xb6, 0x85, 0x35, 0xd8, 0x91,
	0xb8, 0xdb, 0xb2, 0x7b, 0x56, 0x47, 0x2b, 0xe0, 0x27, 0xf0, 0x58, 0x92, 0x76, 0xab, 0xdf, 0xb6,
	0x7a, 0x29, 0x2c, 0xde, 0xc3, 0xee, 0x79, 0xaf, 0x6b, 0x0b, 0x58, 0xc2, 0x18, 0x54, 0x09, 0x1d,
	0xeb, 0xcc, 0x6a, 0x8f, 0xac, 0x8e, 0x56, 0x7e, 0xf7, 0x61, 0xb5, 0x26, 0xca, 0xcd, 0x9a, 0x28,
	0xb7, 0x6b, 0x82, 0xbe, 0x24, 0x04, 0x7d, 0x4f, 0x08, 0xfa, 0x99, 0x10, 0xb4, 0x4a, 0x08, 0xfa,
	0x95, 0x10, 0xf4, 0x3b, 0x21, 0xca, 0x6d, 0x42, 0xd0, 0xd7, 0x0d, 0x51, 0x56, 0x1b, 0xa2, 0xdc,
	0x6c, 0x88, 0xf2, 0xf1, 0x80, 0x2f, 0xc2, 0x68, 0x6e, 0x8c, 0xe7, 0x41, 0x3c, 0x31, 0x1f, 0xfe,
	0xfd, 0x27, 0xd9, 0xe7, 0x45, 0x59, 0xac, 0xe6, 0xf5, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xab,
	0x3a, 0x20, 0x36, 0x1e, 0x03, 0x00, 0x00,
}

func (x State) String() string {
	s, ok := State_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
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
	if this.RequestId != that1.RequestId {
		return false
	}
	if this.State != that1.State {
		return false
	}
	if !this.CheckDuration.Equal(that1.CheckDuration) {
		return false
	}
	if this.OperationType != that1.OperationType {
		return false
	}
	if this.ResourceId != that1.ResourceId {
		return false
	}
	if this.ResourceType != that1.ResourceType {
		return false
	}
	if this.FailureReason != that1.FailureReason {
		return false
	}
	if !this.StartTime.Equal(that1.StartTime) {
		return false
	}
	if !this.FinishTime.Equal(that1.FinishTime) {
		return false
	}
	return true
}
func (this *RequestStatus) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 13)
	s = append(s, "&request.RequestStatus{")
	s = append(s, "RequestId: "+fmt.Sprintf("%#v", this.RequestId)+",\n")
	s = append(s, "State: "+fmt.Sprintf("%#v", this.State)+",\n")
	if this.CheckDuration != nil {
		s = append(s, "CheckDuration: "+fmt.Sprintf("%#v", this.CheckDuration)+",\n")
	}
	s = append(s, "OperationType: "+fmt.Sprintf("%#v", this.OperationType)+",\n")
	s = append(s, "ResourceId: "+fmt.Sprintf("%#v", this.ResourceId)+",\n")
	s = append(s, "ResourceType: "+fmt.Sprintf("%#v", this.ResourceType)+",\n")
	s = append(s, "FailureReason: "+fmt.Sprintf("%#v", this.FailureReason)+",\n")
	if this.StartTime != nil {
		s = append(s, "StartTime: "+fmt.Sprintf("%#v", this.StartTime)+",\n")
	}
	if this.FinishTime != nil {
		s = append(s, "FinishTime: "+fmt.Sprintf("%#v", this.FinishTime)+",\n")
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
		dAtA[i] = 0x52
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
		dAtA[i] = 0x4a
	}
	if len(m.FailureReason) > 0 {
		i -= len(m.FailureReason)
		copy(dAtA[i:], m.FailureReason)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.FailureReason)))
		i--
		dAtA[i] = 0x42
	}
	if len(m.ResourceType) > 0 {
		i -= len(m.ResourceType)
		copy(dAtA[i:], m.ResourceType)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.ResourceType)))
		i--
		dAtA[i] = 0x3a
	}
	if len(m.ResourceId) > 0 {
		i -= len(m.ResourceId)
		copy(dAtA[i:], m.ResourceId)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.ResourceId)))
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
		dAtA[i] = 0x22
	}
	if m.State != 0 {
		i = encodeVarintMessage(dAtA, i, uint64(m.State))
		i--
		dAtA[i] = 0x18
	}
	if len(m.RequestId) > 0 {
		i -= len(m.RequestId)
		copy(dAtA[i:], m.RequestId)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.RequestId)))
		i--
		dAtA[i] = 0x12
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
	l = len(m.RequestId)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.State != 0 {
		n += 1 + sovMessage(uint64(m.State))
	}
	if m.CheckDuration != nil {
		l = m.CheckDuration.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.OperationType)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.ResourceId)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.ResourceType)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.FailureReason)
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
		`RequestId:` + fmt.Sprintf("%v", this.RequestId) + `,`,
		`State:` + fmt.Sprintf("%v", this.State) + `,`,
		`CheckDuration:` + strings.Replace(fmt.Sprintf("%v", this.CheckDuration), "Duration", "types.Duration", 1) + `,`,
		`OperationType:` + fmt.Sprintf("%v", this.OperationType) + `,`,
		`ResourceId:` + fmt.Sprintf("%v", this.ResourceId) + `,`,
		`ResourceType:` + fmt.Sprintf("%v", this.ResourceType) + `,`,
		`FailureReason:` + fmt.Sprintf("%v", this.FailureReason) + `,`,
		`StartTime:` + strings.Replace(fmt.Sprintf("%v", this.StartTime), "Timestamp", "types.Timestamp", 1) + `,`,
		`FinishTime:` + strings.Replace(fmt.Sprintf("%v", this.FinishTime), "Timestamp", "types.Timestamp", 1) + `,`,
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
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RequestId", wireType)
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
			m.RequestId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
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
				m.State |= State(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
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
		case 7:
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
		case 10:
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
