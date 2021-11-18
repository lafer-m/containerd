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

type DefaultNetPolicy int32

const (
	DefaultNetPolicy_Permit DefaultNetPolicy = 0
	DefaultNetPolicy_Deny   DefaultNetPolicy = 1
)

var DefaultNetPolicy_name = map[int32]string{
	0: "Permit",
	1: "Deny",
}

var DefaultNetPolicy_value = map[string]int32{
	"Permit": 0,
	"Deny":   1,
}

func (x DefaultNetPolicy) String() string {
	return proto.EnumName(DefaultNetPolicy_name, int32(x))
}

func (DefaultNetPolicy) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_bfa2a2f42dbbf328, []int{2}
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
	AccessType string `protobuf:"bytes,5,opt,name=AccessType,proto3" json:"AccessType,omitempty"`
	// 是否使用
	IsActive             bool     `protobuf:"varint,6,opt,name=IsActive,proto3" json:"IsActive,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
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

func (m *NetPolicy) GetAccessType() string {
	if m != nil {
		return m.AccessType
	}
	return ""
}

func (m *NetPolicy) GetIsActive() bool {
	if m != nil {
		return m.IsActive
	}
	return false
}

type PolicyGroup struct {
	// 策略组名称
	Name          string       `protobuf:"bytes,1,opt,name=Name,proto3" json:"Name,omitempty"`
	NetworkPolicy []*NetPolicy `protobuf:"bytes,2,rep,name=NetworkPolicy,proto3" json:"NetworkPolicy,omitempty"`
	// 默认策略类型, 全部放行或者全部拦截
	Default              DefaultNetPolicy `protobuf:"varint,3,opt,name=Default,proto3,enum=proto.DefaultNetPolicy" json:"Default,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
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

func (m *PolicyGroup) GetDefault() DefaultNetPolicy {
	if m != nil {
		return m.Default
	}
	return DefaultNetPolicy_Permit
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
	proto.RegisterEnum("proto.DefaultNetPolicy", DefaultNetPolicy_name, DefaultNetPolicy_value)
	proto.RegisterType((*NetPolicy)(nil), "proto.NetPolicy")
	proto.RegisterType((*PolicyGroup)(nil), "proto.PolicyGroup")
	proto.RegisterType((*FetchPolicyReq)(nil), "proto.FetchPolicyReq")
	proto.RegisterType((*FetchPolicyResp)(nil), "proto.FetchPolicyResp")
}

func init() { proto.RegisterFile("proto/netpolicy.proto", fileDescriptor_bfa2a2f42dbbf328) }

var fileDescriptor_bfa2a2f42dbbf328 = []byte{
	// 435 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x52, 0x5d, 0x8b, 0xd3, 0x40,
	0x14, 0xdd, 0x69, 0xda, 0x34, 0xb9, 0xc1, 0x1a, 0x2f, 0xbb, 0x3a, 0x2c, 0x22, 0xa1, 0x28, 0x84,
	0x3e, 0x74, 0xb1, 0x8a, 0x2f, 0xeb, 0xcb, 0x6a, 0x59, 0x29, 0x62, 0x09, 0xd3, 0xea, 0x83, 0x6f,
	0x31, 0x5e, 0x6b, 0xb0, 0x69, 0x62, 0x32, 0x55, 0xfa, 0xe6, 0x0f, 0xf0, 0xcf, 0xf9, 0x8f, 0x24,
	0x77, 0xd2, 0x4f, 0x7d, 0x9a, 0x7b, 0xcf, 0x39, 0xc3, 0x9c, 0x73, 0x12, 0xb8, 0x28, 0xca, 0x5c,
	0xe7, 0x57, 0x2b, 0xd2, 0x45, 0xbe, 0x4c, 0x93, 0xcd, 0x90, 0x77, 0xec, 0xf0, 0xd1, 0xff, 0x23,
	0xc0, 0x9d, 0x92, 0x8e, 0x98, 0xc2, 0x10, 0xda, 0xf3, 0x4d, 0x41, 0x52, 0x04, 0x22, 0xec, 0x8d,
	0xce, 0x8d, 0x74, 0xb8, 0xe3, 0x6b, 0x4e, 0xb1, 0x02, 0x9f, 0x83, 0x13, 0xd5, 0x64, 0x92, 0x2f,
	0x65, 0x8b, 0xd5, 0xf2, 0x54, 0xbd, 0xe5, 0xd5, 0x4e, 0x89, 0x08, 0xed, 0x28, 0x2f, 0xb5, 0xb4,
	0x02, 0x11, 0xba, 0x8a, 0x67, 0x3c, 0x87, 0xce, 0x87, 0x78, 0xb9, 0x26, 0xd9, 0x66, 0xd0, 0x2c,
	0xf8, 0x08, 0xe0, 0x26, 0x49, 0xa8, 0xaa, 0xd8, 0x4f, 0x87, 0xa9, 0x03, 0x04, 0x2f, 0xc1, 0x99,
	0x54, 0x37, 0x89, 0x4e, 0x7f, 0x90, 0xb4, 0x03, 0x11, 0x3a, 0x6a, 0xb7, 0xf7, 0x7f, 0x0b, 0xf0,
	0x8c, 0x85, 0x37, 0x65, 0xbe, 0x2e, 0xea, 0x57, 0xa7, 0x71, 0x66, 0x52, 0xb9, 0x8a, 0x67, 0x7c,
	0x01, 0x77, 0xa6, 0xa4, 0x7f, 0xe6, 0xe5, 0x37, 0xa3, 0x94, 0xad, 0xc0, 0x0a, 0xbd, 0x91, 0x7f,
	0x1a, 0x42, 0x1d, 0xcb, 0xf0, 0x29, 0x74, 0xc7, 0xf4, 0x25, 0x5e, 0x2f, 0x4d, 0x88, 0xde, 0xe8,
	0x41, 0x73, 0xa3, 0x41, 0xf7, 0x17, 0xb7, 0xba, 0xfe, 0x2f, 0x01, 0xbd, 0x5b, 0xd2, 0xc9, 0xd7,
	0x86, 0xa0, 0xef, 0x18, 0x80, 0x67, 0xb2, 0xbc, 0xa5, 0xcd, 0xe4, 0x73, 0x63, 0xec, 0x10, 0x42,
	0x1f, 0xac, 0x77, 0xd5, 0x82, 0xab, 0x75, 0x55, 0x3d, 0xe2, 0x43, 0x70, 0xe7, 0x69, 0x46, 0x95,
	0x8e, 0xb3, 0x82, 0xdf, 0xb6, 0xd4, 0x1e, 0xa8, 0xd9, 0x59, 0xba, 0x58, 0xc5, 0x7a, 0x5d, 0x6e,
	0x9b, 0xdc, 0x03, 0xfd, 0x6b, 0xb8, 0x7b, 0xe4, 0xa0, 0x2a, 0x30, 0x84, 0x0e, 0xb7, 0x23, 0x05,
	0x07, 0xc7, 0x26, 0xc6, 0x41, 0x6f, 0xca, 0x08, 0x06, 0x8f, 0xb9, 0xaa, 0xfd, 0x1f, 0x80, 0x36,
	0xb4, 0x26, 0x91, 0x7f, 0x86, 0x1e, 0x74, 0x67, 0xb4, 0xc8, 0x68, 0xa5, 0x7d, 0x31, 0x78, 0x02,
	0xf7, 0xfe, 0xf9, 0xf2, 0xd8, 0x05, 0x6b, 0xfe, 0xba, 0x96, 0x76, 0xc1, 0x7a, 0x3f, 0x8e, 0x7c,
	0x31, 0x08, 0xc1, 0x3f, 0x6d, 0x0a, 0x01, 0xec, 0x88, 0xca, 0x2c, 0xd5, 0xfe, 0x19, 0x3a, 0xd0,
	0x1e, 0xd3, 0x6a, 0xe3, 0x8b, 0xd1, 0x2d, 0xd8, 0x0d, 0xff, 0x12, 0xbc, 0x03, 0xf7, 0x78, 0xd1,
	0x58, 0x3d, 0xee, 0xf4, 0xf2, 0xfe, 0xff, 0xe0, 0xaa, 0x78, 0x05, 0x1f, 0x9d, 0xe1, 0xd5, 0x35,
	0x73, 0x9f, 0x6c, 0x3e, 0x9e, 0xfd, 0x0d, 0x00, 0x00, 0xff, 0xff, 0xa6, 0x0c, 0x7f, 0xc3, 0x14,
	0x03, 0x00, 0x00,
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
