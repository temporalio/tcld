// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: api/common/v1/message.proto

package common

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

type FailoverType int32

const (
	FAILOVER_TYPE_UNSPECIFIED FailoverType = 0
	FAILOVER_TYPE_GRACEFUL    FailoverType = 1
	FAILOVER_TYPE_FORCE       FailoverType = 2
)

var FailoverType_name = map[int32]string{
	0: "Unspecified",
	1: "Graceful",
	2: "Force",
}

var FailoverType_value = map[string]int32{
	"Unspecified": 0,
	"Graceful":    1,
	"Force":       2,
}

func (FailoverType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_df4c2c740e1454e5, []int{0}
}

type FailoverStatus int32

const (
	FAILOVER_STATUS_UNSPECIFIED FailoverStatus = 0
	FAILOVER_STATUS_SUCCEEDED   FailoverStatus = 1
	FAILOVER_STATUS_FAILED      FailoverStatus = 2
)

var FailoverStatus_name = map[int32]string{
	0: "Unspecified",
	1: "Succeeded",
	2: "Failed",
}

var FailoverStatus_value = map[string]int32{
	"Unspecified": 0,
	"Succeeded":   1,
	"Failed":      2,
}

func (FailoverStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_df4c2c740e1454e5, []int{1}
}

type ReplicaState int32

const (
	REPLICA_STATE_UNSPECIFIED         ReplicaState = 0
	REPLICA_STATE_ACTIVATING          ReplicaState = 1
	REPLICA_STATE_ACTIVATION_FAILED   ReplicaState = 2
	REPLICA_STATE_ACTIVATED           ReplicaState = 3
	REPLICA_STATE_DEACTIVATING        ReplicaState = 4
	REPLICA_STATE_DEACTIVATION_FAILED ReplicaState = 5
	REPLICA_STATE_DEACTIVATED         ReplicaState = 6
)

var ReplicaState_name = map[int32]string{
	0: "Unspecified",
	1: "Activating",
	2: "ActivationFailed",
	3: "Activated",
	4: "Deactivating",
	5: "DeactivationFailed",
	6: "Deactivated",
}

var ReplicaState_value = map[string]int32{
	"Unspecified":        0,
	"Activating":         1,
	"ActivationFailed":   2,
	"Activated":          3,
	"Deactivating":       4,
	"DeactivationFailed": 5,
	"Deactivated":        6,
}

func (ReplicaState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_df4c2c740e1454e5, []int{2}
}

// (-- api-linter: core::0123::resource-annotation=disabled --)
type Region struct {
	// E.g., aws, gcp, azure.
	CloudProvider string `protobuf:"bytes,1,opt,name=cloud_provider,json=cloudProvider,proto3" json:"cloud_provider,omitempty"`
	// Cloud-specific region name. E.g., us-west-2 for AWS and europe-west1 for GCP.
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// The flag indicates if the region supports global namespace.
	SupportGlobalNamespace bool `protobuf:"varint,3,opt,name=support_global_namespace,json=supportGlobalNamespace,proto3" json:"support_global_namespace,omitempty"` // Deprecated: Do not use.
	// The allow list of connection between the current region with a target region.
	ConnectableRegions []*RegionID `protobuf:"bytes,4,rep,name=connectable_regions,json=connectableRegions,proto3" json:"connectable_regions,omitempty"`
}

func (m *Region) Reset()      { *m = Region{} }
func (*Region) ProtoMessage() {}
func (*Region) Descriptor() ([]byte, []int) {
	return fileDescriptor_df4c2c740e1454e5, []int{0}
}
func (m *Region) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Region) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Region.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Region) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Region.Merge(m, src)
}
func (m *Region) XXX_Size() int {
	return m.Size()
}
func (m *Region) XXX_DiscardUnknown() {
	xxx_messageInfo_Region.DiscardUnknown(m)
}

var xxx_messageInfo_Region proto.InternalMessageInfo

func (m *Region) GetCloudProvider() string {
	if m != nil {
		return m.CloudProvider
	}
	return ""
}

func (m *Region) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// Deprecated: Do not use.
func (m *Region) GetSupportGlobalNamespace() bool {
	if m != nil {
		return m.SupportGlobalNamespace
	}
	return false
}

func (m *Region) GetConnectableRegions() []*RegionID {
	if m != nil {
		return m.ConnectableRegions
	}
	return nil
}

type RegionID struct {
	// E.g., aws, gcp, azure.
	CloudProvider string `protobuf:"bytes,1,opt,name=cloud_provider,json=cloudProvider,proto3" json:"cloud_provider,omitempty"`
	// Cloud-specific region name. E.g., us-west-2 for AWS and europe-west1 for GCP.
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *RegionID) Reset()      { *m = RegionID{} }
func (*RegionID) ProtoMessage() {}
func (*RegionID) Descriptor() ([]byte, []int) {
	return fileDescriptor_df4c2c740e1454e5, []int{1}
}
func (m *RegionID) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *RegionID) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_RegionID.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *RegionID) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RegionID.Merge(m, src)
}
func (m *RegionID) XXX_Size() int {
	return m.Size()
}
func (m *RegionID) XXX_DiscardUnknown() {
	xxx_messageInfo_RegionID.DiscardUnknown(m)
}

var xxx_messageInfo_RegionID proto.InternalMessageInfo

func (m *RegionID) GetCloudProvider() string {
	if m != nil {
		return m.CloudProvider
	}
	return ""
}

func (m *RegionID) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type ReplicaStatus struct {
	// The replica located region
	Region *RegionID `protobuf:"bytes,1,opt,name=region,proto3" json:"region,omitempty"`
	// The workflow number to be copied to the replica.
	ToBeReplicatedWorkflowCount int64 `protobuf:"varint,2,opt,name=to_be_replicated_workflow_count,json=toBeReplicatedWorkflowCount,proto3" json:"to_be_replicated_workflow_count,omitempty"`
	// The workflow number that already replicated to the replica.
	ReplicatedWorkflowCount int64 `protobuf:"varint,3,opt,name=replicated_workflow_count,json=replicatedWorkflowCount,proto3" json:"replicated_workflow_count,omitempty"`
	// The estimated time when this replica is ready.
	EstimatedCompletionDuration *types.Duration `protobuf:"bytes,4,opt,name=estimated_completion_duration,json=estimatedCompletionDuration,proto3" json:"estimated_completion_duration,omitempty"`
	// The current status of a replica.
	State ReplicaState `protobuf:"varint,5,opt,name=state,proto3,enum=api.common.v1.ReplicaState" json:"state,omitempty"`
}

func (m *ReplicaStatus) Reset()      { *m = ReplicaStatus{} }
func (*ReplicaStatus) ProtoMessage() {}
func (*ReplicaStatus) Descriptor() ([]byte, []int) {
	return fileDescriptor_df4c2c740e1454e5, []int{2}
}
func (m *ReplicaStatus) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ReplicaStatus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ReplicaStatus.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ReplicaStatus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReplicaStatus.Merge(m, src)
}
func (m *ReplicaStatus) XXX_Size() int {
	return m.Size()
}
func (m *ReplicaStatus) XXX_DiscardUnknown() {
	xxx_messageInfo_ReplicaStatus.DiscardUnknown(m)
}

var xxx_messageInfo_ReplicaStatus proto.InternalMessageInfo

func (m *ReplicaStatus) GetRegion() *RegionID {
	if m != nil {
		return m.Region
	}
	return nil
}

func (m *ReplicaStatus) GetToBeReplicatedWorkflowCount() int64 {
	if m != nil {
		return m.ToBeReplicatedWorkflowCount
	}
	return 0
}

func (m *ReplicaStatus) GetReplicatedWorkflowCount() int64 {
	if m != nil {
		return m.ReplicatedWorkflowCount
	}
	return 0
}

func (m *ReplicaStatus) GetEstimatedCompletionDuration() *types.Duration {
	if m != nil {
		return m.EstimatedCompletionDuration
	}
	return nil
}

func (m *ReplicaStatus) GetState() ReplicaState {
	if m != nil {
		return m.State
	}
	return REPLICA_STATE_UNSPECIFIED
}

func init() {
	proto.RegisterEnum("api.common.v1.FailoverType", FailoverType_name, FailoverType_value)
	proto.RegisterEnum("api.common.v1.FailoverStatus", FailoverStatus_name, FailoverStatus_value)
	proto.RegisterEnum("api.common.v1.ReplicaState", ReplicaState_name, ReplicaState_value)
	proto.RegisterType((*Region)(nil), "api.common.v1.Region")
	proto.RegisterType((*RegionID)(nil), "api.common.v1.RegionID")
	proto.RegisterType((*ReplicaStatus)(nil), "api.common.v1.ReplicaStatus")
}

func init() { proto.RegisterFile("api/common/v1/message.proto", fileDescriptor_df4c2c740e1454e5) }

var fileDescriptor_df4c2c740e1454e5 = []byte{
	// 656 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x94, 0xcf, 0x4e, 0xdb, 0x4c,
	0x14, 0xc5, 0x33, 0x49, 0x88, 0xf8, 0xe6, 0x03, 0x64, 0x0d, 0x12, 0x31, 0xa4, 0x0c, 0x29, 0x15,
	0x52, 0xc4, 0xc2, 0x11, 0x74, 0xd7, 0x76, 0x13, 0xec, 0x09, 0xb5, 0x84, 0x42, 0xe4, 0x24, 0x54,
	0xad, 0x54, 0x59, 0x8e, 0x33, 0x44, 0x56, 0x6d, 0x8f, 0x65, 0x4f, 0x82, 0xba, 0xeb, 0x23, 0xf4,
	0x31, 0xfa, 0x28, 0x95, 0xba, 0x61, 0xd1, 0x05, 0xcb, 0x62, 0x36, 0x5d, 0x22, 0xf5, 0x05, 0xaa,
	0x8c, 0x1d, 0x37, 0xe6, 0x4f, 0x37, 0xdd, 0x39, 0xf7, 0xfc, 0xce, 0xdc, 0x7b, 0x3c, 0x37, 0x86,
	0x35, 0x2b, 0x70, 0x9a, 0x36, 0xf3, 0x3c, 0xe6, 0x37, 0xa7, 0x07, 0x4d, 0x8f, 0x46, 0x91, 0x35,
	0xa6, 0x4a, 0x10, 0x32, 0xce, 0xd0, 0xaa, 0x15, 0x38, 0x4a, 0x22, 0x2a, 0xd3, 0x83, 0x2d, 0x3c,
	0x66, 0x6c, 0xec, 0xd2, 0xa6, 0x10, 0x87, 0x93, 0xf3, 0xe6, 0x68, 0x12, 0x5a, 0xdc, 0x61, 0x7e,
	0x82, 0xef, 0x7e, 0x03, 0xb0, 0x62, 0xd0, 0xb1, 0xc3, 0x7c, 0xb4, 0x07, 0xd7, 0x6c, 0x97, 0x4d,
	0x46, 0x66, 0x10, 0xb2, 0xa9, 0x33, 0xa2, 0xa1, 0x0c, 0xea, 0xa0, 0xf1, 0x9f, 0xb1, 0x2a, 0xaa,
	0xdd, 0xb4, 0x88, 0x10, 0x2c, 0xfb, 0x96, 0x47, 0xe5, 0xa2, 0x10, 0xc5, 0x33, 0x7a, 0x05, 0xe5,
	0x68, 0x12, 0x04, 0x2c, 0xe4, 0xe6, 0xd8, 0x65, 0x43, 0xcb, 0x35, 0x67, 0xe5, 0x28, 0xb0, 0x6c,
	0x2a, 0x97, 0xea, 0xa0, 0xb1, 0x7c, 0x54, 0x94, 0x81, 0xb1, 0x91, 0x32, 0xc7, 0x02, 0xe9, 0xcc,
	0x09, 0xf4, 0x1a, 0xae, 0xdb, 0xcc, 0xf7, 0xa9, 0xcd, 0xad, 0xa1, 0x4b, 0xcd, 0x50, 0x8c, 0x13,
	0xc9, 0xe5, 0x7a, 0xa9, 0xf1, 0xff, 0x61, 0x55, 0xc9, 0x05, 0x52, 0x92, 0x61, 0x75, 0xcd, 0x40,
	0x0b, 0x9e, 0xa4, 0x18, 0xed, 0x12, 0xb8, 0x3c, 0xd7, 0xff, 0x21, 0xce, 0xee, 0xf7, 0x22, 0x5c,
	0x35, 0x68, 0xe0, 0x3a, 0xb6, 0xd5, 0xe3, 0x16, 0x9f, 0x44, 0xa8, 0x09, 0x2b, 0xc9, 0x58, 0xe2,
	0x90, 0xbf, 0x4c, 0x95, 0x62, 0x48, 0x83, 0x3b, 0x9c, 0x99, 0xc3, 0x59, 0x1a, 0x71, 0x0e, 0xa7,
	0x23, 0xf3, 0x82, 0x85, 0x1f, 0xce, 0x5d, 0x76, 0x61, 0xda, 0x6c, 0xe2, 0x73, 0xd1, 0xb1, 0x64,
	0xd4, 0x38, 0x3b, 0xa2, 0x46, 0x06, 0xbd, 0x49, 0x19, 0x75, 0x86, 0xa0, 0x17, 0x70, 0xf3, 0x71,
	0x7f, 0x49, 0xf8, 0xab, 0xe1, 0x23, 0xde, 0xf7, 0x70, 0x9b, 0x46, 0xdc, 0xf1, 0x84, 0xd5, 0x66,
	0x5e, 0xe0, 0xd2, 0xd9, 0xbd, 0x9b, 0xf3, 0x05, 0x90, 0xcb, 0x22, 0xc9, 0xa6, 0x92, 0x6c, 0x88,
	0x32, 0xdf, 0x10, 0x45, 0x4b, 0x01, 0xa3, 0x96, 0xf9, 0xd5, 0xcc, 0x3e, 0x17, 0xd1, 0x01, 0x5c,
	0x8a, 0xb8, 0xc5, 0xa9, 0xbc, 0x54, 0x07, 0x8d, 0xb5, 0xc3, 0xda, 0xbd, 0x17, 0x92, 0xbd, 0x3e,
	0x6a, 0x24, 0xe4, 0xfe, 0x10, 0xae, 0xb4, 0x2d, 0xc7, 0x65, 0x53, 0x1a, 0xf6, 0x3f, 0x06, 0x14,
	0x6d, 0xc3, 0xcd, 0x76, 0x4b, 0x3f, 0x39, 0x3d, 0x23, 0x86, 0xd9, 0x7f, 0xdb, 0x25, 0xe6, 0xa0,
	0xd3, 0xeb, 0x12, 0x55, 0x6f, 0xeb, 0x44, 0x93, 0x0a, 0x68, 0x0b, 0x6e, 0xe4, 0xe5, 0x63, 0xa3,
	0xa5, 0x92, 0xf6, 0xe0, 0x44, 0x02, 0xa8, 0x0a, 0xd7, 0xf3, 0x5a, 0xfb, 0xd4, 0x50, 0x89, 0x54,
	0xdc, 0x77, 0xe1, 0xda, 0xbc, 0x47, 0x7a, 0x75, 0x3b, 0xb0, 0x96, 0xa1, 0xbd, 0x7e, 0xab, 0x3f,
	0xe8, 0xdd, 0xe9, 0xb3, 0x38, 0x46, 0x0a, 0xf4, 0x06, 0xaa, 0x4a, 0x88, 0x46, 0x34, 0x09, 0xe4,
	0xc6, 0x48, 0xe5, 0xd9, 0x6f, 0xa2, 0x49, 0xc5, 0xfd, 0x5f, 0x00, 0xae, 0x2c, 0x26, 0x9d, 0x9d,
	0x65, 0x90, 0xee, 0x89, 0xae, 0xb6, 0x04, 0x7b, 0x37, 0xd2, 0x13, 0x28, 0xe7, 0xe5, 0x96, 0xda,
	0xd7, 0xcf, 0x5a, 0x7d, 0xbd, 0x73, 0x2c, 0x01, 0xf4, 0x0c, 0xee, 0x3c, 0xac, 0x9e, 0x76, 0xb2,
	0x96, 0xa8, 0x06, 0xab, 0x0f, 0x42, 0x44, 0x93, 0x4a, 0x08, 0xc3, 0xad, 0xbc, 0xa8, 0x91, 0x85,
	0x0e, 0x65, 0xb4, 0x07, 0x9f, 0x3e, 0xa6, 0xff, 0xe9, 0xb1, 0x74, 0x3f, 0x45, 0x86, 0x11, 0x4d,
	0xaa, 0x1c, 0x9d, 0x5d, 0x5e, 0xe3, 0xc2, 0xd5, 0x35, 0x2e, 0xdc, 0x5e, 0x63, 0xf0, 0x29, 0xc6,
	0xe0, 0x4b, 0x8c, 0xc1, 0xd7, 0x18, 0x83, 0xcb, 0x18, 0x83, 0x1f, 0x31, 0x06, 0x3f, 0x63, 0x5c,
	0xb8, 0x8d, 0x31, 0xf8, 0x7c, 0x83, 0x0b, 0x97, 0x37, 0xb8, 0x70, 0x75, 0x83, 0x0b, 0xef, 0xea,
	0xdc, 0x0b, 0x42, 0x57, 0x11, 0xff, 0xbe, 0x66, 0xee, 0x0b, 0xf6, 0x32, 0x79, 0x1a, 0x56, 0xc4,
	0x0a, 0x3e, 0xff, 0x1d, 0x00, 0x00, 0xff, 0xff, 0xcf, 0x10, 0xc1, 0x95, 0xe0, 0x04, 0x00, 0x00,
}

func (x FailoverType) String() string {
	s, ok := FailoverType_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (x FailoverStatus) String() string {
	s, ok := FailoverStatus_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (x ReplicaState) String() string {
	s, ok := ReplicaState_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (this *Region) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Region)
	if !ok {
		that2, ok := that.(Region)
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
	if this.CloudProvider != that1.CloudProvider {
		return false
	}
	if this.Name != that1.Name {
		return false
	}
	if this.SupportGlobalNamespace != that1.SupportGlobalNamespace {
		return false
	}
	if len(this.ConnectableRegions) != len(that1.ConnectableRegions) {
		return false
	}
	for i := range this.ConnectableRegions {
		if !this.ConnectableRegions[i].Equal(that1.ConnectableRegions[i]) {
			return false
		}
	}
	return true
}
func (this *RegionID) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*RegionID)
	if !ok {
		that2, ok := that.(RegionID)
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
	if this.CloudProvider != that1.CloudProvider {
		return false
	}
	if this.Name != that1.Name {
		return false
	}
	return true
}
func (this *ReplicaStatus) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*ReplicaStatus)
	if !ok {
		that2, ok := that.(ReplicaStatus)
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
	if !this.Region.Equal(that1.Region) {
		return false
	}
	if this.ToBeReplicatedWorkflowCount != that1.ToBeReplicatedWorkflowCount {
		return false
	}
	if this.ReplicatedWorkflowCount != that1.ReplicatedWorkflowCount {
		return false
	}
	if !this.EstimatedCompletionDuration.Equal(that1.EstimatedCompletionDuration) {
		return false
	}
	if this.State != that1.State {
		return false
	}
	return true
}
func (this *Region) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 8)
	s = append(s, "&common.Region{")
	s = append(s, "CloudProvider: "+fmt.Sprintf("%#v", this.CloudProvider)+",\n")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "SupportGlobalNamespace: "+fmt.Sprintf("%#v", this.SupportGlobalNamespace)+",\n")
	if this.ConnectableRegions != nil {
		s = append(s, "ConnectableRegions: "+fmt.Sprintf("%#v", this.ConnectableRegions)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *RegionID) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 6)
	s = append(s, "&common.RegionID{")
	s = append(s, "CloudProvider: "+fmt.Sprintf("%#v", this.CloudProvider)+",\n")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *ReplicaStatus) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 9)
	s = append(s, "&common.ReplicaStatus{")
	if this.Region != nil {
		s = append(s, "Region: "+fmt.Sprintf("%#v", this.Region)+",\n")
	}
	s = append(s, "ToBeReplicatedWorkflowCount: "+fmt.Sprintf("%#v", this.ToBeReplicatedWorkflowCount)+",\n")
	s = append(s, "ReplicatedWorkflowCount: "+fmt.Sprintf("%#v", this.ReplicatedWorkflowCount)+",\n")
	if this.EstimatedCompletionDuration != nil {
		s = append(s, "EstimatedCompletionDuration: "+fmt.Sprintf("%#v", this.EstimatedCompletionDuration)+",\n")
	}
	s = append(s, "State: "+fmt.Sprintf("%#v", this.State)+",\n")
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
func (m *Region) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Region) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Region) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.ConnectableRegions) > 0 {
		for iNdEx := len(m.ConnectableRegions) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.ConnectableRegions[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintMessage(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x22
		}
	}
	if m.SupportGlobalNamespace {
		i--
		if m.SupportGlobalNamespace {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x18
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.CloudProvider) > 0 {
		i -= len(m.CloudProvider)
		copy(dAtA[i:], m.CloudProvider)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.CloudProvider)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *RegionID) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *RegionID) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *RegionID) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.CloudProvider) > 0 {
		i -= len(m.CloudProvider)
		copy(dAtA[i:], m.CloudProvider)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.CloudProvider)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ReplicaStatus) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ReplicaStatus) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ReplicaStatus) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.State != 0 {
		i = encodeVarintMessage(dAtA, i, uint64(m.State))
		i--
		dAtA[i] = 0x28
	}
	if m.EstimatedCompletionDuration != nil {
		{
			size, err := m.EstimatedCompletionDuration.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if m.ReplicatedWorkflowCount != 0 {
		i = encodeVarintMessage(dAtA, i, uint64(m.ReplicatedWorkflowCount))
		i--
		dAtA[i] = 0x18
	}
	if m.ToBeReplicatedWorkflowCount != 0 {
		i = encodeVarintMessage(dAtA, i, uint64(m.ToBeReplicatedWorkflowCount))
		i--
		dAtA[i] = 0x10
	}
	if m.Region != nil {
		{
			size, err := m.Region.MarshalToSizedBuffer(dAtA[:i])
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
func (m *Region) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.CloudProvider)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.SupportGlobalNamespace {
		n += 2
	}
	if len(m.ConnectableRegions) > 0 {
		for _, e := range m.ConnectableRegions {
			l = e.Size()
			n += 1 + l + sovMessage(uint64(l))
		}
	}
	return n
}

func (m *RegionID) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.CloudProvider)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func (m *ReplicaStatus) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Region != nil {
		l = m.Region.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.ToBeReplicatedWorkflowCount != 0 {
		n += 1 + sovMessage(uint64(m.ToBeReplicatedWorkflowCount))
	}
	if m.ReplicatedWorkflowCount != 0 {
		n += 1 + sovMessage(uint64(m.ReplicatedWorkflowCount))
	}
	if m.EstimatedCompletionDuration != nil {
		l = m.EstimatedCompletionDuration.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.State != 0 {
		n += 1 + sovMessage(uint64(m.State))
	}
	return n
}

func sovMessage(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMessage(x uint64) (n int) {
	return sovMessage(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *Region) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForConnectableRegions := "[]*RegionID{"
	for _, f := range this.ConnectableRegions {
		repeatedStringForConnectableRegions += strings.Replace(f.String(), "RegionID", "RegionID", 1) + ","
	}
	repeatedStringForConnectableRegions += "}"
	s := strings.Join([]string{`&Region{`,
		`CloudProvider:` + fmt.Sprintf("%v", this.CloudProvider) + `,`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`SupportGlobalNamespace:` + fmt.Sprintf("%v", this.SupportGlobalNamespace) + `,`,
		`ConnectableRegions:` + repeatedStringForConnectableRegions + `,`,
		`}`,
	}, "")
	return s
}
func (this *RegionID) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&RegionID{`,
		`CloudProvider:` + fmt.Sprintf("%v", this.CloudProvider) + `,`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ReplicaStatus) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ReplicaStatus{`,
		`Region:` + strings.Replace(this.Region.String(), "RegionID", "RegionID", 1) + `,`,
		`ToBeReplicatedWorkflowCount:` + fmt.Sprintf("%v", this.ToBeReplicatedWorkflowCount) + `,`,
		`ReplicatedWorkflowCount:` + fmt.Sprintf("%v", this.ReplicatedWorkflowCount) + `,`,
		`EstimatedCompletionDuration:` + strings.Replace(fmt.Sprintf("%v", this.EstimatedCompletionDuration), "Duration", "types.Duration", 1) + `,`,
		`State:` + fmt.Sprintf("%v", this.State) + `,`,
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
func (m *Region) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: Region: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Region: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CloudProvider", wireType)
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
			m.CloudProvider = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
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
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field SupportGlobalNamespace", wireType)
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
			m.SupportGlobalNamespace = bool(v != 0)
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ConnectableRegions", wireType)
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
			m.ConnectableRegions = append(m.ConnectableRegions, &RegionID{})
			if err := m.ConnectableRegions[len(m.ConnectableRegions)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
func (m *RegionID) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: RegionID: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: RegionID: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CloudProvider", wireType)
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
			m.CloudProvider = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
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
			m.Name = string(dAtA[iNdEx:postIndex])
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
func (m *ReplicaStatus) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: ReplicaStatus: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ReplicaStatus: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Region", wireType)
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
			if m.Region == nil {
				m.Region = &RegionID{}
			}
			if err := m.Region.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ToBeReplicatedWorkflowCount", wireType)
			}
			m.ToBeReplicatedWorkflowCount = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ToBeReplicatedWorkflowCount |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ReplicatedWorkflowCount", wireType)
			}
			m.ReplicatedWorkflowCount = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ReplicatedWorkflowCount |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EstimatedCompletionDuration", wireType)
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
			if m.EstimatedCompletionDuration == nil {
				m.EstimatedCompletionDuration = &types.Duration{}
			}
			if err := m.EstimatedCompletionDuration.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
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
				m.State |= ReplicaState(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
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
