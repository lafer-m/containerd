// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/containerd/containerd/api/services/netpolicy/v1/netpolicy.proto

package netpolicy

import (
	context "context"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

type NetPolicy struct {
	// 指定策略类型 IP 网段
	Type string `protobuf:"bytes,1,opt,name=Type,proto3" json:"Type,omitempty"`
	// 在哪个协议上生效 tcp/udp
	Protocol string `protobuf:"bytes,2,opt,name=Protocol,proto3" json:"Protocol,omitempty"`
	// 作用的端口
	Port int32 `protobuf:"varint,3,opt,name=Port,proto3" json:"Port,omitempty"`
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

func (m *NetPolicy) Reset()      { *m = NetPolicy{} }
func (*NetPolicy) ProtoMessage() {}
func (*NetPolicy) Descriptor() ([]byte, []int) {
	return fileDescriptor_604dab4962cf3a36, []int{0}
}
func (m *NetPolicy) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *NetPolicy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_NetPolicy.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *NetPolicy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NetPolicy.Merge(m, src)
}
func (m *NetPolicy) XXX_Size() int {
	return m.Size()
}
func (m *NetPolicy) XXX_DiscardUnknown() {
	xxx_messageInfo_NetPolicy.DiscardUnknown(m)
}

var xxx_messageInfo_NetPolicy proto.InternalMessageInfo

type PolicyGroup struct {
	// 策略组名称
	Name                 string       `protobuf:"bytes,1,opt,name=Name,proto3" json:"Name,omitempty"`
	NetworkPolicy        []*NetPolicy `protobuf:"bytes,2,rep,name=NetworkPolicy,proto3" json:"NetworkPolicy,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *PolicyGroup) Reset()      { *m = PolicyGroup{} }
func (*PolicyGroup) ProtoMessage() {}
func (*PolicyGroup) Descriptor() ([]byte, []int) {
	return fileDescriptor_604dab4962cf3a36, []int{1}
}
func (m *PolicyGroup) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *PolicyGroup) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_PolicyGroup.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *PolicyGroup) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PolicyGroup.Merge(m, src)
}
func (m *PolicyGroup) XXX_Size() int {
	return m.Size()
}
func (m *PolicyGroup) XXX_DiscardUnknown() {
	xxx_messageInfo_PolicyGroup.DiscardUnknown(m)
}

var xxx_messageInfo_PolicyGroup proto.InternalMessageInfo

type FetchPolicyReq struct {
	AccessKeyId          string   `protobuf:"bytes,1,opt,name=AccessKeyId,proto3" json:"AccessKeyId,omitempty"`
	Msg                  string   `protobuf:"bytes,2,opt,name=Msg,proto3" json:"Msg,omitempty"`
	Timestamp            int64    `protobuf:"varint,3,opt,name=Timestamp,proto3" json:"Timestamp,omitempty"`
	Signature            string   `protobuf:"bytes,4,opt,name=Signature,proto3" json:"Signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FetchPolicyReq) Reset()      { *m = FetchPolicyReq{} }
func (*FetchPolicyReq) ProtoMessage() {}
func (*FetchPolicyReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_604dab4962cf3a36, []int{2}
}
func (m *FetchPolicyReq) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *FetchPolicyReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_FetchPolicyReq.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *FetchPolicyReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FetchPolicyReq.Merge(m, src)
}
func (m *FetchPolicyReq) XXX_Size() int {
	return m.Size()
}
func (m *FetchPolicyReq) XXX_DiscardUnknown() {
	xxx_messageInfo_FetchPolicyReq.DiscardUnknown(m)
}

var xxx_messageInfo_FetchPolicyReq proto.InternalMessageInfo

type FetchPolicyResp struct {
	Group                *PolicyGroup `protobuf:"bytes,1,opt,name=Group,proto3" json:"Group,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *FetchPolicyResp) Reset()      { *m = FetchPolicyResp{} }
func (*FetchPolicyResp) ProtoMessage() {}
func (*FetchPolicyResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_604dab4962cf3a36, []int{3}
}
func (m *FetchPolicyResp) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *FetchPolicyResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_FetchPolicyResp.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *FetchPolicyResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FetchPolicyResp.Merge(m, src)
}
func (m *FetchPolicyResp) XXX_Size() int {
	return m.Size()
}
func (m *FetchPolicyResp) XXX_DiscardUnknown() {
	xxx_messageInfo_FetchPolicyResp.DiscardUnknown(m)
}

var xxx_messageInfo_FetchPolicyResp proto.InternalMessageInfo

func init() {
	proto.RegisterType((*NetPolicy)(nil), "containerd.services.netpolicy.v1.NetPolicy")
	proto.RegisterType((*PolicyGroup)(nil), "containerd.services.netpolicy.v1.PolicyGroup")
	proto.RegisterType((*FetchPolicyReq)(nil), "containerd.services.netpolicy.v1.FetchPolicyReq")
	proto.RegisterType((*FetchPolicyResp)(nil), "containerd.services.netpolicy.v1.FetchPolicyResp")
}

func init() {
	proto.RegisterFile("github.com/containerd/containerd/api/services/netpolicy/v1/netpolicy.proto", fileDescriptor_604dab4962cf3a36)
}

var fileDescriptor_604dab4962cf3a36 = []byte{
	// 409 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x52, 0x4f, 0x8b, 0xd3, 0x40,
	0x1c, 0xdd, 0xd9, 0x6c, 0xca, 0xf6, 0x17, 0xfc, 0xc3, 0xe0, 0x21, 0x2c, 0x12, 0x42, 0x4e, 0x01,
	0x31, 0xb1, 0xf5, 0xe8, 0x69, 0x55, 0x94, 0x55, 0x2c, 0x35, 0x2e, 0x7b, 0xf0, 0x20, 0x64, 0x67,
	0x87, 0x76, 0xb0, 0xc9, 0x8c, 0x33, 0x93, 0x48, 0xc1, 0x43, 0xbf, 0x8a, 0xdf, 0xa6, 0x47, 0x8f,
	0x1e, 0x6d, 0x3e, 0x89, 0x64, 0x92, 0x26, 0xe9, 0xa9, 0xe8, 0xed, 0xbd, 0xf7, 0xfb, 0xf7, 0xf2,
	0x32, 0xf0, 0x6e, 0xc1, 0xf4, 0xb2, 0xb8, 0x8d, 0x08, 0xcf, 0x62, 0xc2, 0x73, 0x9d, 0xb2, 0x9c,
	0xca, 0xbb, 0x21, 0x4c, 0x05, 0x8b, 0x15, 0x95, 0x25, 0x23, 0x54, 0xc5, 0x39, 0xd5, 0x82, 0xaf,
	0x18, 0x59, 0xc7, 0xe5, 0xa4, 0x27, 0x91, 0x90, 0x5c, 0x73, 0xec, 0xf7, 0x53, 0xd1, 0x7e, 0x22,
	0xea, 0x9b, 0xca, 0x49, 0xf0, 0x13, 0xc1, 0x78, 0x46, 0xf5, 0xdc, 0x08, 0x18, 0xc3, 0xd9, 0xf5,
	0x5a, 0x50, 0x17, 0xf9, 0x28, 0x1c, 0x27, 0x06, 0xe3, 0x0b, 0x38, 0x9f, 0xd7, 0xcb, 0x08, 0x5f,
	0xb9, 0xa7, 0x46, 0xef, 0x78, 0xdd, 0x3f, 0xe7, 0x52, 0xbb, 0x96, 0x8f, 0x42, 0x3b, 0x31, 0x18,
	0x3f, 0x02, 0xfb, 0x26, 0x5d, 0x15, 0xd4, 0x3d, 0x33, 0xcd, 0x0d, 0xc1, 0x1e, 0xc0, 0x25, 0x21,
	0x54, 0x29, 0xb3, 0xdf, 0x36, 0xa5, 0x81, 0x52, 0x5f, 0xb9, 0x52, 0x97, 0x44, 0xb3, 0x92, 0xba,
	0x23, 0x1f, 0x85, 0xe7, 0x49, 0xc7, 0x03, 0x0d, 0x4e, 0xe3, 0xef, 0xad, 0xe4, 0x85, 0xa8, 0x8f,
	0xce, 0xd2, 0xac, 0x33, 0x59, 0x63, 0xfc, 0x11, 0xee, 0xcd, 0xa8, 0xfe, 0xce, 0xe5, 0xd7, 0xa6,
	0xd3, 0x3d, 0xf5, 0xad, 0xd0, 0x99, 0x3e, 0x89, 0x8e, 0x05, 0x10, 0x75, 0x1f, 0x9f, 0x1c, 0x6e,
	0x08, 0x36, 0x08, 0xee, 0xbf, 0xa1, 0x9a, 0x2c, 0xdb, 0x32, 0xfd, 0x86, 0x7d, 0x70, 0x1a, 0xcb,
	0xef, 0xe9, 0xfa, 0xea, 0xae, 0x35, 0x30, 0x94, 0xf0, 0x43, 0xb0, 0x3e, 0xa8, 0x45, 0x9b, 0x53,
	0x0d, 0xf1, 0x63, 0x18, 0x5f, 0xb3, 0x8c, 0x2a, 0x9d, 0x66, 0xc2, 0xe4, 0x64, 0x25, 0xbd, 0x50,
	0x57, 0x3f, 0xb1, 0x45, 0x9e, 0xea, 0x42, 0xee, 0x03, 0xeb, 0x85, 0xe0, 0x06, 0x1e, 0x1c, 0x38,
	0x50, 0x02, 0xbf, 0x02, 0xdb, 0xa4, 0x60, 0x8e, 0x3b, 0xd3, 0xa7, 0xc7, 0x3f, 0x70, 0x10, 0x5d,
	0xd2, 0xcc, 0x4e, 0x7f, 0xc0, 0xa8, 0xfd, 0xe1, 0x12, 0x9c, 0xc1, 0x05, 0xfc, 0xec, 0xf8, 0xba,
	0xc3, 0x48, 0x2e, 0x26, 0xff, 0x38, 0xa1, 0xc4, 0xcb, 0x2f, 0xdb, 0x9d, 0x77, 0xf2, 0x7b, 0xe7,
	0x9d, 0x6c, 0x2a, 0x0f, 0x6d, 0x2b, 0x0f, 0xfd, 0xaa, 0x3c, 0xf4, 0xa7, 0xf2, 0xd0, 0xe7, 0xd7,
	0xff, 0xff, 0xf4, 0x5f, 0x74, 0xe4, 0x76, 0x64, 0xde, 0xfe, 0xf3, 0xbf, 0x01, 0x00, 0x00, 0xff,
	0xff, 0xae, 0x8c, 0x86, 0x3a, 0x49, 0x03, 0x00, 0x00,
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
	err := c.cc.Invoke(ctx, "/containerd.services.netpolicy.v1.Policy/FetchPolicy", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PolicyServer is the server API for Policy service.
type PolicyServer interface {
	FetchPolicy(context.Context, *FetchPolicyReq) (*FetchPolicyResp, error)
}

// UnimplementedPolicyServer can be embedded to have forward compatible implementations.
type UnimplementedPolicyServer struct {
}

func (*UnimplementedPolicyServer) FetchPolicy(ctx context.Context, req *FetchPolicyReq) (*FetchPolicyResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FetchPolicy not implemented")
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
		FullMethod: "/containerd.services.netpolicy.v1.Policy/FetchPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServer).FetchPolicy(ctx, req.(*FetchPolicyReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _Policy_serviceDesc = grpc.ServiceDesc{
	ServiceName: "containerd.services.netpolicy.v1.Policy",
	HandlerType: (*PolicyServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FetchPolicy",
			Handler:    _Policy_FetchPolicy_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "github.com/containerd/containerd/api/services/netpolicy/v1/netpolicy.proto",
}

func (m *NetPolicy) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *NetPolicy) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *NetPolicy) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.IsActive {
		i--
		if m.IsActive {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x30
	}
	if len(m.AccessType) > 0 {
		i -= len(m.AccessType)
		copy(dAtA[i:], m.AccessType)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.AccessType)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.Value) > 0 {
		i -= len(m.Value)
		copy(dAtA[i:], m.Value)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.Value)))
		i--
		dAtA[i] = 0x22
	}
	if m.Port != 0 {
		i = encodeVarintNetpolicy(dAtA, i, uint64(m.Port))
		i--
		dAtA[i] = 0x18
	}
	if len(m.Protocol) > 0 {
		i -= len(m.Protocol)
		copy(dAtA[i:], m.Protocol)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.Protocol)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Type) > 0 {
		i -= len(m.Type)
		copy(dAtA[i:], m.Type)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.Type)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *PolicyGroup) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *PolicyGroup) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PolicyGroup) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.NetworkPolicy) > 0 {
		for iNdEx := len(m.NetworkPolicy) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.NetworkPolicy[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintNetpolicy(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *FetchPolicyReq) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *FetchPolicyReq) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *FetchPolicyReq) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Signature) > 0 {
		i -= len(m.Signature)
		copy(dAtA[i:], m.Signature)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.Signature)))
		i--
		dAtA[i] = 0x22
	}
	if m.Timestamp != 0 {
		i = encodeVarintNetpolicy(dAtA, i, uint64(m.Timestamp))
		i--
		dAtA[i] = 0x18
	}
	if len(m.Msg) > 0 {
		i -= len(m.Msg)
		copy(dAtA[i:], m.Msg)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.Msg)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.AccessKeyId) > 0 {
		i -= len(m.AccessKeyId)
		copy(dAtA[i:], m.AccessKeyId)
		i = encodeVarintNetpolicy(dAtA, i, uint64(len(m.AccessKeyId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *FetchPolicyResp) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *FetchPolicyResp) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *FetchPolicyResp) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Group != nil {
		{
			size, err := m.Group.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintNetpolicy(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintNetpolicy(dAtA []byte, offset int, v uint64) int {
	offset -= sovNetpolicy(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *NetPolicy) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Type)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	l = len(m.Protocol)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	if m.Port != 0 {
		n += 1 + sovNetpolicy(uint64(m.Port))
	}
	l = len(m.Value)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	l = len(m.AccessType)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	if m.IsActive {
		n += 2
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *PolicyGroup) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	if len(m.NetworkPolicy) > 0 {
		for _, e := range m.NetworkPolicy {
			l = e.Size()
			n += 1 + l + sovNetpolicy(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *FetchPolicyReq) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.AccessKeyId)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	l = len(m.Msg)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	if m.Timestamp != 0 {
		n += 1 + sovNetpolicy(uint64(m.Timestamp))
	}
	l = len(m.Signature)
	if l > 0 {
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *FetchPolicyResp) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Group != nil {
		l = m.Group.Size()
		n += 1 + l + sovNetpolicy(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovNetpolicy(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozNetpolicy(x uint64) (n int) {
	return sovNetpolicy(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *NetPolicy) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&NetPolicy{`,
		`Type:` + fmt.Sprintf("%v", this.Type) + `,`,
		`Protocol:` + fmt.Sprintf("%v", this.Protocol) + `,`,
		`Port:` + fmt.Sprintf("%v", this.Port) + `,`,
		`Value:` + fmt.Sprintf("%v", this.Value) + `,`,
		`AccessType:` + fmt.Sprintf("%v", this.AccessType) + `,`,
		`IsActive:` + fmt.Sprintf("%v", this.IsActive) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *PolicyGroup) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForNetworkPolicy := "[]*NetPolicy{"
	for _, f := range this.NetworkPolicy {
		repeatedStringForNetworkPolicy += strings.Replace(f.String(), "NetPolicy", "NetPolicy", 1) + ","
	}
	repeatedStringForNetworkPolicy += "}"
	s := strings.Join([]string{`&PolicyGroup{`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`NetworkPolicy:` + repeatedStringForNetworkPolicy + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *FetchPolicyReq) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&FetchPolicyReq{`,
		`AccessKeyId:` + fmt.Sprintf("%v", this.AccessKeyId) + `,`,
		`Msg:` + fmt.Sprintf("%v", this.Msg) + `,`,
		`Timestamp:` + fmt.Sprintf("%v", this.Timestamp) + `,`,
		`Signature:` + fmt.Sprintf("%v", this.Signature) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *FetchPolicyResp) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&FetchPolicyResp{`,
		`Group:` + strings.Replace(this.Group.String(), "PolicyGroup", "PolicyGroup", 1) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringNetpolicy(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *NetPolicy) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetpolicy
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
			return fmt.Errorf("proto: NetPolicy: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: NetPolicy: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Type = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Protocol", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Protocol = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Port", wireType)
			}
			m.Port = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Port |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Value = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccessType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccessType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field IsActive", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
			m.IsActive = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipNetpolicy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *PolicyGroup) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetpolicy
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
			return fmt.Errorf("proto: PolicyGroup: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PolicyGroup: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NetworkPolicy", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.NetworkPolicy = append(m.NetworkPolicy, &NetPolicy{})
			if err := m.NetworkPolicy[len(m.NetworkPolicy)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetpolicy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *FetchPolicyReq) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetpolicy
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
			return fmt.Errorf("proto: FetchPolicyReq: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: FetchPolicyReq: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccessKeyId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccessKeyId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Msg", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Msg = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			m.Timestamp = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Timestamp |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signature", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Signature = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetpolicy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *FetchPolicyResp) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetpolicy
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
			return fmt.Errorf("proto: FetchPolicyResp: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: FetchPolicyResp: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Group", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetpolicy
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
				return ErrInvalidLengthNetpolicy
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Group == nil {
				m.Group = &PolicyGroup{}
			}
			if err := m.Group.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetpolicy(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthNetpolicy
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipNetpolicy(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowNetpolicy
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
					return 0, ErrIntOverflowNetpolicy
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
					return 0, ErrIntOverflowNetpolicy
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
				return 0, ErrInvalidLengthNetpolicy
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupNetpolicy
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthNetpolicy
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthNetpolicy        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowNetpolicy          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupNetpolicy = fmt.Errorf("proto: unexpected end of group")
)
