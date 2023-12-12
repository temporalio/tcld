// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: temporal/api/cloud/operation/v1/message.proto

package operation

import (
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

type AsyncOperation struct {
	// The operation id
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The current state of this operation
	// Possible values are: PENDING, IN_PROGRESS, FAILED, CANCELLED, FULFILLED
	State string `protobuf:"bytes,2,opt,name=state,proto3" json:"state,omitempty"`
	// The recommended duration to check back for an update in the operation's state
	CheckDuration *types.Duration `protobuf:"bytes,3,opt,name=check_duration,json=checkDuration,proto3" json:"check_duration,omitempty"`
	// The type of operation being performed
	OperationType string `protobuf:"bytes,4,opt,name=operation_type,json=operationType,proto3" json:"operation_type,omitempty"`
	// The input to the operation being performed
	OperationInput *types.Any `protobuf:"bytes,5,opt,name=operation_input,json=operationInput,proto3" json:"operation_input,omitempty"`
	// If the operation failed, the reason for the failure
	FailureReason string `protobuf:"bytes,6,opt,name=failure_reason,json=failureReason,proto3" json:"failure_reason,omitempty"`
	// The date and time when the operation initiated
	StartedTime *types.Timestamp `protobuf:"bytes,7,opt,name=started_time,json=startedTime,proto3" json:"started_time,omitempty"`
	// The date and time when the operation completed
	FinishedTime *types.Timestamp `protobuf:"bytes,8,opt,name=finished_time,json=finishedTime,proto3" json:"finished_time,omitempty"`
}

func (m *AsyncOperation) Reset()      { *m = AsyncOperation{} }
func (*AsyncOperation) ProtoMessage() {}
func (*AsyncOperation) Descriptor() ([]byte, []int) {
	return fileDescriptor_e895f88c45383e9d, []int{0}
}
func (m *AsyncOperation) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AsyncOperation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AsyncOperation.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AsyncOperation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AsyncOperation.Merge(m, src)
}
func (m *AsyncOperation) XXX_Size() int {
	return m.Size()
}
func (m *AsyncOperation) XXX_DiscardUnknown() {
	xxx_messageInfo_AsyncOperation.DiscardUnknown(m)
}

var xxx_messageInfo_AsyncOperation proto.InternalMessageInfo

func (m *AsyncOperation) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *AsyncOperation) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

func (m *AsyncOperation) GetCheckDuration() *types.Duration {
	if m != nil {
		return m.CheckDuration
	}
	return nil
}

func (m *AsyncOperation) GetOperationType() string {
	if m != nil {
		return m.OperationType
	}
	return ""
}

func (m *AsyncOperation) GetOperationInput() *types.Any {
	if m != nil {
		return m.OperationInput
	}
	return nil
}

func (m *AsyncOperation) GetFailureReason() string {
	if m != nil {
		return m.FailureReason
	}
	return ""
}

func (m *AsyncOperation) GetStartedTime() *types.Timestamp {
	if m != nil {
		return m.StartedTime
	}
	return nil
}

func (m *AsyncOperation) GetFinishedTime() *types.Timestamp {
	if m != nil {
		return m.FinishedTime
	}
	return nil
}

func init() {
	proto.RegisterType((*AsyncOperation)(nil), "temporal.api.cloud.operation.v1.AsyncOperation")
}

func init() {
	proto.RegisterFile("temporal/api/cloud/operation/v1/message.proto", fileDescriptor_e895f88c45383e9d)
}

var fileDescriptor_e895f88c45383e9d = []byte{
	// 399 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0x31, 0x8f, 0xd3, 0x30,
	0x18, 0x86, 0xe3, 0x1e, 0x77, 0x80, 0xef, 0x1a, 0x24, 0xeb, 0x86, 0x5c, 0x07, 0xdf, 0x09, 0x09,
	0xe9, 0x16, 0x6c, 0x1d, 0x8c, 0xe8, 0x04, 0x87, 0x58, 0x98, 0x90, 0xa2, 0x4e, 0x2c, 0x91, 0x9b,
	0xb8, 0xa9, 0x45, 0x12, 0x5b, 0xb1, 0x53, 0x29, 0x1b, 0x0b, 0x3b, 0x3f, 0x83, 0x9f, 0xc2, 0xd8,
	0xb1, 0x23, 0x4d, 0x17, 0xc6, 0xfe, 0x04, 0x14, 0x27, 0x4e, 0xa5, 0x56, 0xe8, 0xc6, 0xef, 0xfd,
	0x9e, 0x37, 0x8f, 0x63, 0x19, 0xbe, 0x36, 0x3c, 0x57, 0xb2, 0x64, 0x19, 0x65, 0x4a, 0xd0, 0x38,
	0x93, 0x55, 0x42, 0xa5, 0xe2, 0x25, 0x33, 0x42, 0x16, 0x74, 0x79, 0x47, 0x73, 0xae, 0x35, 0x4b,
	0x39, 0x51, 0xa5, 0x34, 0x12, 0x5d, 0x3b, 0x9c, 0x30, 0x25, 0x88, 0xc5, 0xc9, 0x80, 0x93, 0xe5,
	0xdd, 0x04, 0xa7, 0x52, 0xa6, 0x19, 0xa7, 0x16, 0x9f, 0x55, 0x73, 0x9a, 0x54, 0xfd, 0xd2, 0x26,
	0x93, 0xeb, 0xc3, 0xbd, 0x11, 0x39, 0xd7, 0x86, 0xe5, 0xaa, 0x07, 0xae, 0x0e, 0x01, 0x56, 0xd4,
	0xdd, 0xea, 0xe5, 0x8f, 0x13, 0xe8, 0x3f, 0xe8, 0xba, 0x88, 0xbf, 0x38, 0x23, 0xf2, 0xe1, 0x48,
	0x24, 0x01, 0xb8, 0x01, 0xb7, 0xcf, 0xc3, 0x91, 0x48, 0xd0, 0x25, 0x3c, 0xd5, 0x86, 0x19, 0x1e,
	0x8c, 0x6c, 0xd4, 0x0d, 0xe8, 0x03, 0xf4, 0xe3, 0x05, 0x8f, 0xbf, 0x45, 0xee, 0x30, 0xc1, 0xc9,
	0x0d, 0xb8, 0x3d, 0x7f, 0x73, 0x45, 0x3a, 0x19, 0x71, 0x32, 0xf2, 0xa9, 0x07, 0xc2, 0xb1, 0x2d,
	0xb8, 0x11, 0xbd, 0x82, 0xfe, 0xf0, 0x9b, 0x91, 0xa9, 0x15, 0x0f, 0x9e, 0x58, 0xc1, 0x78, 0x48,
	0xa7, 0xb5, 0xe2, 0xe8, 0x1e, 0xbe, 0xd8, 0x63, 0xa2, 0x50, 0x95, 0x09, 0x4e, 0xad, 0xe9, 0xf2,
	0xc8, 0xf4, 0x50, 0xd4, 0xe1, 0xfe, 0x9b, 0x9f, 0x5b, 0xb6, 0xb5, 0xcc, 0x99, 0xc8, 0xaa, 0x92,
	0x47, 0x25, 0x67, 0x5a, 0x16, 0xc1, 0x59, 0x67, 0xe9, 0xd3, 0xd0, 0x86, 0xe8, 0x1e, 0x5e, 0x68,
	0xc3, 0x4a, 0xc3, 0x93, 0xa8, 0xbd, 0xbd, 0xe0, 0xa9, 0x55, 0x4c, 0x8e, 0x14, 0x53, 0x77, 0xb5,
	0xe1, 0x79, 0xcf, 0xb7, 0x09, 0x7a, 0x0f, 0xc7, 0x73, 0x51, 0x08, 0xbd, 0x70, 0xfd, 0x67, 0x8f,
	0xf6, 0x2f, 0x5c, 0xa1, 0x8d, 0x3e, 0xf2, 0xd5, 0x06, 0x7b, 0xeb, 0x0d, 0xf6, 0x76, 0x1b, 0x0c,
	0xbe, 0x37, 0x18, 0xfc, 0x6a, 0x30, 0xf8, 0xdd, 0x60, 0xb0, 0x6a, 0x30, 0xf8, 0xd3, 0x60, 0xf0,
	0xb7, 0xc1, 0xde, 0xae, 0xc1, 0xe0, 0xe7, 0x16, 0x7b, 0xab, 0x2d, 0xf6, 0xd6, 0x5b, 0xec, 0x7d,
	0xa5, 0xa9, 0x24, 0xc3, 0xeb, 0x11, 0xf2, 0x3f, 0xef, 0xed, 0xdd, 0x30, 0xcc, 0xce, 0xec, 0x41,
	0xde, 0xfe, 0x0b, 0x00, 0x00, 0xff, 0xff, 0x89, 0x4d, 0x07, 0xb4, 0xa3, 0x02, 0x00, 0x00,
}

func (this *AsyncOperation) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AsyncOperation)
	if !ok {
		that2, ok := that.(AsyncOperation)
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
	if this.State != that1.State {
		return false
	}
	if !this.CheckDuration.Equal(that1.CheckDuration) {
		return false
	}
	if this.OperationType != that1.OperationType {
		return false
	}
	if !this.OperationInput.Equal(that1.OperationInput) {
		return false
	}
	if this.FailureReason != that1.FailureReason {
		return false
	}
	if !this.StartedTime.Equal(that1.StartedTime) {
		return false
	}
	if !this.FinishedTime.Equal(that1.FinishedTime) {
		return false
	}
	return true
}
func (this *AsyncOperation) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 12)
	s = append(s, "&operation.AsyncOperation{")
	s = append(s, "Id: "+fmt.Sprintf("%#v", this.Id)+",\n")
	s = append(s, "State: "+fmt.Sprintf("%#v", this.State)+",\n")
	if this.CheckDuration != nil {
		s = append(s, "CheckDuration: "+fmt.Sprintf("%#v", this.CheckDuration)+",\n")
	}
	s = append(s, "OperationType: "+fmt.Sprintf("%#v", this.OperationType)+",\n")
	if this.OperationInput != nil {
		s = append(s, "OperationInput: "+fmt.Sprintf("%#v", this.OperationInput)+",\n")
	}
	s = append(s, "FailureReason: "+fmt.Sprintf("%#v", this.FailureReason)+",\n")
	if this.StartedTime != nil {
		s = append(s, "StartedTime: "+fmt.Sprintf("%#v", this.StartedTime)+",\n")
	}
	if this.FinishedTime != nil {
		s = append(s, "FinishedTime: "+fmt.Sprintf("%#v", this.FinishedTime)+",\n")
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
func (m *AsyncOperation) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AsyncOperation) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AsyncOperation) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.FinishedTime != nil {
		{
			size, err := m.FinishedTime.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x42
	}
	if m.StartedTime != nil {
		{
			size, err := m.StartedTime.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x3a
	}
	if len(m.FailureReason) > 0 {
		i -= len(m.FailureReason)
		copy(dAtA[i:], m.FailureReason)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.FailureReason)))
		i--
		dAtA[i] = 0x32
	}
	if m.OperationInput != nil {
		{
			size, err := m.OperationInput.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x2a
	}
	if len(m.OperationType) > 0 {
		i -= len(m.OperationType)
		copy(dAtA[i:], m.OperationType)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.OperationType)))
		i--
		dAtA[i] = 0x22
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
		dAtA[i] = 0x1a
	}
	if len(m.State) > 0 {
		i -= len(m.State)
		copy(dAtA[i:], m.State)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.State)))
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
func (m *AsyncOperation) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
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
	l = len(m.OperationType)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.OperationInput != nil {
		l = m.OperationInput.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.FailureReason)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.StartedTime != nil {
		l = m.StartedTime.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.FinishedTime != nil {
		l = m.FinishedTime.Size()
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
func (this *AsyncOperation) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AsyncOperation{`,
		`Id:` + fmt.Sprintf("%v", this.Id) + `,`,
		`State:` + fmt.Sprintf("%v", this.State) + `,`,
		`CheckDuration:` + strings.Replace(fmt.Sprintf("%v", this.CheckDuration), "Duration", "types.Duration", 1) + `,`,
		`OperationType:` + fmt.Sprintf("%v", this.OperationType) + `,`,
		`OperationInput:` + strings.Replace(fmt.Sprintf("%v", this.OperationInput), "Any", "types.Any", 1) + `,`,
		`FailureReason:` + fmt.Sprintf("%v", this.FailureReason) + `,`,
		`StartedTime:` + strings.Replace(fmt.Sprintf("%v", this.StartedTime), "Timestamp", "types.Timestamp", 1) + `,`,
		`FinishedTime:` + strings.Replace(fmt.Sprintf("%v", this.FinishedTime), "Timestamp", "types.Timestamp", 1) + `,`,
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
func (m *AsyncOperation) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: AsyncOperation: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AsyncOperation: illegal tag %d (wire type %d)", fieldNum, wire)
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
		case 3:
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
		case 4:
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
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field OperationInput", wireType)
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
			if m.OperationInput == nil {
				m.OperationInput = &types.Any{}
			}
			if err := m.OperationInput.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
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
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StartedTime", wireType)
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
			if m.StartedTime == nil {
				m.StartedTime = &types.Timestamp{}
			}
			if err := m.StartedTime.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FinishedTime", wireType)
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
			if m.FinishedTime == nil {
				m.FinishedTime = &types.Timestamp{}
			}
			if err := m.FinishedTime.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
