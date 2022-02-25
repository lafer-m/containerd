// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/netpolicy.proto

package proto

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type NetPolicyType int32

const (
	NetPolicyType_IP      NetPolicyType = 0
	NetPolicyType_Segment NetPolicyType = 1
)

var NetPolicyType_name = map[int32]string{
	0: "IP",
	1: "Segment",
}

var NetPolicyType_value = map[string]int32{
	"IP":      0,
	"Segment": 1,
}

func (x NetPolicyType) String() string {
	return proto.EnumName(NetPolicyType_name, int32(x))
}

func (NetPolicyType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{0}
}

type NetPolicyProtocol int32

const (
	NetPolicyProtocol_TCP NetPolicyProtocol = 0
	NetPolicyProtocol_UDP NetPolicyProtocol = 1
)

var NetPolicyProtocol_name = map[int32]string{
	0: "TCP",
	1: "UDP",
}

var NetPolicyProtocol_value = map[string]int32{
	"TCP": 0,
	"UDP": 1,
}

func (x NetPolicyProtocol) String() string {
	return proto.EnumName(NetPolicyProtocol_name, int32(x))
}

func (NetPolicyProtocol) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{1}
}

type NetPolicyAccessType int32

const (
	NetPolicyAccessType_Permit       NetPolicyAccessType = 0
	NetPolicyAccessType_Deny         NetPolicyAccessType = 1
	NetPolicyAccessType_RejectICMP   NetPolicyAccessType = 2
	NetPolicyAccessType_RejectTcpRST NetPolicyAccessType = 3
)

var NetPolicyAccessType_name = map[int32]string{
	0: "Permit",
	1: "Deny",
	2: "RejectICMP",
	3: "RejectTcpRST",
}

var NetPolicyAccessType_value = map[string]int32{
	"Permit":       0,
	"Deny":         1,
	"RejectICMP":   2,
	"RejectTcpRST": 3,
}

func (x NetPolicyAccessType) String() string {
	return proto.EnumName(NetPolicyAccessType_name, int32(x))
}

func (NetPolicyAccessType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{2}
}

type PolicyDirection int32

const (
	PolicyDirection_Input  PolicyDirection = 0
	PolicyDirection_Output PolicyDirection = 1
)

var PolicyDirection_name = map[int32]string{
	0: "Input",
	1: "Output",
}

var PolicyDirection_value = map[string]int32{
	"Input":  0,
	"Output": 1,
}

func (x PolicyDirection) String() string {
	return proto.EnumName(PolicyDirection_name, int32(x))
}

func (PolicyDirection) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{3}
}

type NetPolicy struct {
	// 指定策略类型 IP 网段
	Type NetPolicyType `protobuf:"varint,1,opt,name=Type,proto3,enum=proto.NetPolicyType" json:"Type,omitempty"`
	// 在哪个协议上生效 tcp/udp
	Protocol NetPolicyProtocol `protobuf:"varint,2,opt,name=Protocol,proto3,enum=proto.NetPolicyProtocol" json:"Protocol,omitempty"`
	// 作用的端口
	// 支持单个端口 80
	// 支持多个端口. 以 逗号 分割, 80,81
	// 支持端口范围 8080-8088
	Port string `protobuf:"bytes,3,opt,name=Port,proto3" json:"Port,omitempty"`
	// ip地址
	Value string `protobuf:"bytes,4,opt,name=Value,proto3" json:"Value,omitempty"`
	// 允许访问, 或者拒绝
	AccessType NetPolicyAccessType `protobuf:"varint,5,opt,name=AccessType,proto3,enum=proto.NetPolicyAccessType" json:"AccessType,omitempty"`
	// 是否使用
	IsActive bool `protobuf:"varint,6,opt,name=IsActive,proto3" json:"IsActive,omitempty"`
	// 策略的方向, input or output
	Direction            PolicyDirection `protobuf:"varint,7,opt,name=Direction,proto3,enum=proto.PolicyDirection" json:"Direction,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *NetPolicy) Reset()         { *m = NetPolicy{} }
func (m *NetPolicy) String() string { return proto.CompactTextString(m) }
func (*NetPolicy) ProtoMessage()    {}
func (*NetPolicy) Descriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{0}
}

func (m *NetPolicy) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NetPolicy.Unmarshal(m, b)
}
func (m *NetPolicy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NetPolicy.Marshal(b, m, deterministic)
}
func (m *NetPolicy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetPolicy.Merge(m, src)
}
func (m *NetPolicy) XXX_Size() int {
	return xxx_messageInfo_NetPolicy.Size(m)
}
func (m *NetPolicy) XXX_DiscardUnknown() {
	xxx_messageInfo_NetPolicy.DiscardUnknown(m)
}

var xxx_messageInfo_NetPolicy proto.InternalMessageInfo

func (m *NetPolicy) GetType() NetPolicyType {
	if m != nil {
		return m.Type
	}
	return NetPolicyType_IP
}

func (m *NetPolicy) GetProtocol() NetPolicyProtocol {
	if m != nil {
		return m.Protocol
	}
	return NetPolicyProtocol_TCP
}

func (m *NetPolicy) GetPort() string {
	if m != nil {
		return m.Port
	}
	return ""
}

func (m *NetPolicy) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

func (m *NetPolicy) GetAccessType() NetPolicyAccessType {
	if m != nil {
		return m.AccessType
	}
	return NetPolicyAccessType_Permit
}

func (m *NetPolicy) GetIsActive() bool {
	if m != nil {
		return m.IsActive
	}
	return false
}

func (m *NetPolicy) GetDirection() PolicyDirection {
	if m != nil {
		return m.Direction
	}
	return PolicyDirection_Input
}

type PolicyGroup struct {
	// 策略组名称
	Name          string       `protobuf:"bytes,1,opt,name=Name,proto3" json:"Name,omitempty"`
	NetworkPolicy []*NetPolicy `protobuf:"bytes,2,rep,name=NetworkPolicy,proto3" json:"NetworkPolicy,omitempty"`
	// 默认策略类型, 全部放行或者全部拦截
	Default              NetPolicyAccessType `protobuf:"varint,3,opt,name=Default,proto3,enum=proto.NetPolicyAccessType" json:"Default,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *PolicyGroup) Reset()         { *m = PolicyGroup{} }
func (m *PolicyGroup) String() string { return proto.CompactTextString(m) }
func (*PolicyGroup) ProtoMessage()    {}
func (*PolicyGroup) Descriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{1}
}

func (m *PolicyGroup) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PolicyGroup.Unmarshal(m, b)
}
func (m *PolicyGroup) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PolicyGroup.Marshal(b, m, deterministic)
}
func (m *PolicyGroup) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PolicyGroup.Merge(m, src)
}
func (m *PolicyGroup) XXX_Size() int {
	return xxx_messageInfo_PolicyGroup.Size(m)
}
func (m *PolicyGroup) XXX_DiscardUnknown() {
	xxx_messageInfo_PolicyGroup.DiscardUnknown(m)
}

var xxx_messageInfo_PolicyGroup proto.InternalMessageInfo

func (m *PolicyGroup) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *PolicyGroup) GetNetworkPolicy() []*NetPolicy {
	if m != nil {
		return m.NetworkPolicy
	}
	return nil
}

func (m *PolicyGroup) GetDefault() NetPolicyAccessType {
	if m != nil {
		return m.Default
	}
	return NetPolicyAccessType_Permit
}

type FetchPolicyReq struct {
	AccessKeyId          string   `protobuf:"bytes,1,opt,name=AccessKeyId,proto3" json:"AccessKeyId,omitempty"`
	Msg                  string   `protobuf:"bytes,2,opt,name=Msg,proto3" json:"Msg,omitempty"`
	Timestamp            int64    `protobuf:"varint,3,opt,name=Timestamp,proto3" json:"Timestamp,omitempty"`
	Signature            string   `protobuf:"bytes,4,opt,name=Signature,proto3" json:"Signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FetchPolicyReq) Reset()         { *m = FetchPolicyReq{} }
func (m *FetchPolicyReq) String() string { return proto.CompactTextString(m) }
func (*FetchPolicyReq) ProtoMessage()    {}
func (*FetchPolicyReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{2}
}

func (m *FetchPolicyReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FetchPolicyReq.Unmarshal(m, b)
}
func (m *FetchPolicyReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FetchPolicyReq.Marshal(b, m, deterministic)
}
func (m *FetchPolicyReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FetchPolicyReq.Merge(m, src)
}
func (m *FetchPolicyReq) XXX_Size() int {
	return xxx_messageInfo_FetchPolicyReq.Size(m)
}
func (m *FetchPolicyReq) XXX_DiscardUnknown() {
	xxx_messageInfo_FetchPolicyReq.DiscardUnknown(m)
}

var xxx_messageInfo_FetchPolicyReq proto.InternalMessageInfo

func (m *FetchPolicyReq) GetAccessKeyId() string {
	if m != nil {
		return m.AccessKeyId
	}
	return ""
}

func (m *FetchPolicyReq) GetMsg() string {
	if m != nil {
		return m.Msg
	}
	return ""
}

func (m *FetchPolicyReq) GetTimestamp() int64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *FetchPolicyReq) GetSignature() string {
	if m != nil {
		return m.Signature
	}
	return ""
}

type FetchPolicyResp struct {
	Group                []*PolicyGroup `protobuf:"bytes,1,rep,name=Group,proto3" json:"Group,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *FetchPolicyResp) Reset()         { *m = FetchPolicyResp{} }
func (m *FetchPolicyResp) String() string { return proto.CompactTextString(m) }
func (*FetchPolicyResp) ProtoMessage()    {}
func (*FetchPolicyResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{3}
}

func (m *FetchPolicyResp) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FetchPolicyResp.Unmarshal(m, b)
}
func (m *FetchPolicyResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FetchPolicyResp.Marshal(b, m, deterministic)
}
func (m *FetchPolicyResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FetchPolicyResp.Merge(m, src)
}
func (m *FetchPolicyResp) XXX_Size() int {
	return xxx_messageInfo_FetchPolicyResp.Size(m)
}
func (m *FetchPolicyResp) XXX_DiscardUnknown() {
	xxx_messageInfo_FetchPolicyResp.DiscardUnknown(m)
}

var xxx_messageInfo_FetchPolicyResp proto.InternalMessageInfo

func (m *FetchPolicyResp) GetGroup() []*PolicyGroup {
	if m != nil {
		return m.Group
	}
	return nil
}

func init() {
	proto.RegisterEnum("proto.NetPolicyType", NetPolicyType_name, NetPolicyType_value)
	proto.RegisterEnum("proto.NetPolicyProtocol", NetPolicyProtocol_name, NetPolicyProtocol_value)
	proto.RegisterEnum("proto.NetPolicyAccessType", NetPolicyAccessType_name, NetPolicyAccessType_value)
	proto.RegisterEnum("proto.PolicyDirection", PolicyDirection_name, PolicyDirection_value)
	proto.RegisterType((*NetPolicy)(nil), "proto.NetPolicy")
	proto.RegisterType((*PolicyGroup)(nil), "proto.PolicyGroup")
	proto.RegisterType((*FetchPolicyReq)(nil), "proto.FetchPolicyReq")
	proto.RegisterType((*FetchPolicyResp)(nil), "proto.FetchPolicyResp")
}

func init() { proto.RegisterFile("proto/netpolicy.proto", fileDescriptor_bfa2a2f42dbbf328) }

var fileDescriptor_bfa2a2f42dbbf328 = []byte{
	// 504 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xcf, 0x6e, 0xd3, 0x40,
	0x10, 0xc6, 0xbb, 0x71, 0xe2, 0xc4, 0x63, 0x48, 0x97, 0xa1, 0xad, 0xac, 0x88, 0x83, 0x15, 0x81,
	0x64, 0xe5, 0x90, 0x4a, 0x21, 0xe2, 0x40, 0xb9, 0x94, 0x46, 0x45, 0x16, 0x4a, 0xb0, 0x36, 0x86,
	0x03, 0x37, 0x63, 0x96, 0x60, 0x88, 0xff, 0x60, 0xaf, 0x41, 0xb9, 0xf1, 0x06, 0x3c, 0x04, 0x2f,
	0x8a, 0xbc, 0xeb, 0xc4, 0x49, 0xa8, 0x7a, 0xda, 0x9d, 0xf9, 0x7e, 0x9a, 0x9d, 0xf9, 0x66, 0xe1,
	0x3c, 0xcb, 0x53, 0x91, 0x5e, 0x26, 0x5c, 0x64, 0xe9, 0x3a, 0x0a, 0x37, 0x63, 0x19, 0x63, 0x47,
	0x1e, 0xc3, 0xbf, 0x2d, 0x30, 0x16, 0x5c, 0x78, 0x52, 0x42, 0x07, 0xda, 0xfe, 0x26, 0xe3, 0x16,
	0xb1, 0x89, 0xd3, 0x9f, 0x9c, 0x29, 0x74, 0xbc, 0xd3, 0x2b, 0x8d, 0x49, 0x02, 0xa7, 0xd0, 0xf3,
	0x2a, 0x31, 0x4c, 0xd7, 0x56, 0x4b, 0xd2, 0xd6, 0x31, 0xbd, 0xd5, 0xd9, 0x8e, 0x44, 0x84, 0xb6,
	0x97, 0xe6, 0xc2, 0xd2, 0x6c, 0xe2, 0x18, 0x4c, 0xde, 0xf1, 0x0c, 0x3a, 0x1f, 0x82, 0x75, 0xc9,
	0xad, 0xb6, 0x4c, 0xaa, 0x00, 0x5f, 0x02, 0x5c, 0x87, 0x21, 0x2f, 0x0a, 0xd9, 0x4f, 0x47, 0xbe,
	0x30, 0x38, 0x7e, 0xa1, 0x21, 0xd8, 0x1e, 0x8d, 0x03, 0xe8, 0xb9, 0xc5, 0x75, 0x28, 0xa2, 0x9f,
	0xdc, 0xd2, 0x6d, 0xe2, 0xf4, 0xd8, 0x2e, 0xc6, 0x29, 0x18, 0xb3, 0x28, 0xe7, 0xa1, 0x88, 0xd2,
	0xc4, 0xea, 0xca, 0xb2, 0x17, 0x75, 0x59, 0x55, 0x73, 0xa7, 0xb2, 0x06, 0x1c, 0xfe, 0x21, 0x60,
	0x2a, 0xf9, 0x4d, 0x9e, 0x96, 0x59, 0x35, 0xc7, 0x22, 0x88, 0x95, 0x4f, 0x06, 0x93, 0x77, 0x7c,
	0x01, 0x0f, 0x17, 0x5c, 0xfc, 0x4a, 0xf3, 0xef, 0x8a, 0xb4, 0x5a, 0xb6, 0xe6, 0x98, 0x13, 0x7a,
	0xdc, 0x34, 0x3b, 0xc4, 0x70, 0x0a, 0xdd, 0x19, 0xff, 0x12, 0x94, 0x6b, 0x65, 0xcb, 0xfd, 0x63,
	0x6e, 0xd1, 0xe1, 0x6f, 0x02, 0xfd, 0x5b, 0x2e, 0xc2, 0xaf, 0x75, 0x51, 0xfe, 0x03, 0x6d, 0x30,
	0x15, 0xf9, 0x96, 0x6f, 0xdc, 0xcf, 0x75, 0x6f, 0xfb, 0x29, 0xa4, 0xa0, 0xcd, 0x8b, 0x95, 0xdc,
	0x97, 0xc1, 0xaa, 0x2b, 0x3e, 0x01, 0xc3, 0x8f, 0x62, 0x5e, 0x88, 0x20, 0xce, 0xe4, 0xf3, 0x1a,
	0x6b, 0x12, 0x95, 0xba, 0x8c, 0x56, 0x49, 0x20, 0xca, 0x7c, 0xbb, 0x9e, 0x26, 0x31, 0xbc, 0x82,
	0xd3, 0x83, 0x0e, 0x8a, 0x0c, 0x1d, 0xe8, 0x48, 0x83, 0x2c, 0x22, 0x67, 0xc7, 0x03, 0x67, 0xa5,
	0xc2, 0x14, 0x30, 0x7a, 0x2a, 0xdd, 0x6a, 0xbe, 0x15, 0xea, 0xd0, 0x72, 0x3d, 0x7a, 0x82, 0x26,
	0x74, 0x97, 0x7c, 0x15, 0xf3, 0x44, 0x50, 0x32, 0x7a, 0x06, 0x8f, 0xfe, 0xfb, 0x4e, 0xd8, 0x05,
	0xcd, 0xbf, 0xa9, 0xd0, 0x2e, 0x68, 0xef, 0x67, 0x1e, 0x25, 0xa3, 0x39, 0x3c, 0xbe, 0xc3, 0x2c,
	0x04, 0xd0, 0x3d, 0x9e, 0xc7, 0x91, 0xa0, 0x27, 0xd8, 0x83, 0xf6, 0x8c, 0x27, 0x1b, 0x4a, 0xb0,
	0x0f, 0xc0, 0xf8, 0x37, 0x1e, 0x0a, 0xf7, 0x66, 0xee, 0xd1, 0x16, 0x52, 0x78, 0xa0, 0x62, 0x3f,
	0xcc, 0xd8, 0xd2, 0xa7, 0xda, 0xc8, 0x81, 0xd3, 0xa3, 0xbf, 0x80, 0x06, 0x74, 0xdc, 0x24, 0x2b,
	0xab, 0x4a, 0x00, 0xfa, 0xbb, 0x52, 0x54, 0x77, 0x32, 0xb9, 0x05, 0xbd, 0xde, 0xe2, 0x2b, 0x30,
	0xf7, 0xcc, 0xc0, 0xf3, 0x7a, 0xf2, 0xc3, 0x15, 0x0d, 0x2e, 0xee, 0x4a, 0x17, 0xd9, 0x6b, 0xf8,
	0xd8, 0x1b, 0x5f, 0x5e, 0x49, 0xed, 0x93, 0x2e, 0x8f, 0xe7, 0xff, 0x02, 0x00, 0x00, 0xff, 0xff,
	0x48, 0x59, 0x4e, 0xd4, 0xb8, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// PolicyClient is the client API for Policy service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PolicyClient interface {
	FetchPolicy(ctx context.Context, in *FetchPolicyReq, opts ...grpc.CallOption) (*FetchPolicyResp, error)
}

type policyClient struct {
	cc *grpc.ClientConn
}

func NewPolicyClient(cc *grpc.ClientConn) PolicyClient {
	return &policyClient{cc}
}

func (c *policyClient) FetchPolicy(ctx context.Context, in *FetchPolicyReq, opts ...grpc.CallOption) (*FetchPolicyResp, error) {
	out := new(FetchPolicyResp)
	err := c.cc.Invoke(ctx, "/proto.Policy/FetchPolicy", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PolicyServer is the server API for Policy service.
type PolicyServer interface {
	FetchPolicy(context.Context, *FetchPolicyReq) (*FetchPolicyResp, error)
}

func RegisterPolicyServer(s *grpc.Server, srv PolicyServer) {
	s.RegisterService(&_Policy_serviceDesc, srv)
}

func _Policy_FetchPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchPolicyReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServer).FetchPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Policy/FetchPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServer).FetchPolicy(ctx, req.(*FetchPolicyReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _Policy_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Policy",
	HandlerType: (*PolicyServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FetchPolicy",
			Handler:    _Policy_FetchPolicy_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/netpolicy.proto",
}
