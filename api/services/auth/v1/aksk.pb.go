// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/containerd/containerd/api/services/auth/v1/aksk.proto

package auth

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

type GetAKSKReq struct {
	// 任务临时的 token, 由服务端下发任务时携带
	Token string `protobuf:"bytes,1,opt,name=Token,proto3" json:"Token,omitempty"`
	// 时间戳, 校验数据的时效性
	Timestamp            int64    `protobuf:"varint,2,opt,name=Timestamp,proto3" json:"Timestamp,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetAKSKReq) Reset()      { *m = GetAKSKReq{} }
func (*GetAKSKReq) ProtoMessage() {}
func (*GetAKSKReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_4d053653f09d3908, []int{0}
}
func (m *GetAKSKReq) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GetAKSKReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GetAKSKReq.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GetAKSKReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetAKSKReq.Merge(m, src)
}
func (m *GetAKSKReq) XXX_Size() int {
	return m.Size()
}
func (m *GetAKSKReq) XXX_DiscardUnknown() {
	xxx_messageInfo_GetAKSKReq.DiscardUnknown(m)
}

var xxx_messageInfo_GetAKSKReq proto.InternalMessageInfo

type GetAKSKResp struct {
	AccessKeyId          string   `protobuf:"bytes,1,opt,name=AccessKeyId,proto3" json:"AccessKeyId,omitempty"`
	SecretAccessKey      string   `protobuf:"bytes,2,opt,name=SecretAccessKey,proto3" json:"SecretAccessKey,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetAKSKResp) Reset()      { *m = GetAKSKResp{} }
func (*GetAKSKResp) ProtoMessage() {}
func (*GetAKSKResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_4d053653f09d3908, []int{1}
}
func (m *GetAKSKResp) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GetAKSKResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GetAKSKResp.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GetAKSKResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetAKSKResp.Merge(m, src)
}
func (m *GetAKSKResp) XXX_Size() int {
	return m.Size()
}
func (m *GetAKSKResp) XXX_DiscardUnknown() {
	xxx_messageInfo_GetAKSKResp.DiscardUnknown(m)
}

var xxx_messageInfo_GetAKSKResp proto.InternalMessageInfo

type VerifyAKSKReq struct {
	AccessKeyId          string   `protobuf:"bytes,1,opt,name=AccessKeyId,proto3" json:"AccessKeyId,omitempty"`
	Msg                  string   `protobuf:"bytes,2,opt,name=Msg,proto3" json:"Msg,omitempty"`
	Timestamp            int64    `protobuf:"varint,3,opt,name=Timestamp,proto3" json:"Timestamp,omitempty"`
	Signature            string   `protobuf:"bytes,4,opt,name=Signature,proto3" json:"Signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VerifyAKSKReq) Reset()      { *m = VerifyAKSKReq{} }
func (*VerifyAKSKReq) ProtoMessage() {}
func (*VerifyAKSKReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_4d053653f09d3908, []int{2}
}
func (m *VerifyAKSKReq) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *VerifyAKSKReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_VerifyAKSKReq.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *VerifyAKSKReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyAKSKReq.Merge(m, src)
}
func (m *VerifyAKSKReq) XXX_Size() int {
	return m.Size()
}
func (m *VerifyAKSKReq) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyAKSKReq.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyAKSKReq proto.InternalMessageInfo

type VerifyASKSResp struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VerifyASKSResp) Reset()      { *m = VerifyASKSResp{} }
func (*VerifyASKSResp) ProtoMessage() {}
func (*VerifyASKSResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_4d053653f09d3908, []int{3}
}
func (m *VerifyASKSResp) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *VerifyASKSResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_VerifyASKSResp.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *VerifyASKSResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VerifyASKSResp.Merge(m, src)
}
func (m *VerifyASKSResp) XXX_Size() int {
	return m.Size()
}
func (m *VerifyASKSResp) XXX_DiscardUnknown() {
	xxx_messageInfo_VerifyASKSResp.DiscardUnknown(m)
}

var xxx_messageInfo_VerifyASKSResp proto.InternalMessageInfo

func init() {
	proto.RegisterType((*GetAKSKReq)(nil), "proto.GetAKSKReq")
	proto.RegisterType((*GetAKSKResp)(nil), "proto.GetAKSKResp")
	proto.RegisterType((*VerifyAKSKReq)(nil), "proto.VerifyAKSKReq")
	proto.RegisterType((*VerifyASKSResp)(nil), "proto.VerifyASKSResp")
}

func init() {
	proto.RegisterFile("github.com/containerd/containerd/api/services/auth/v1/aksk.proto", fileDescriptor_4d053653f09d3908)
}

var fileDescriptor_4d053653f09d3908 = []byte{
	// 336 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0xbf, 0x4f, 0xc2, 0x40,
	0x14, 0xc7, 0x39, 0x11, 0x13, 0x1e, 0x11, 0xe1, 0x82, 0x09, 0x21, 0xa6, 0x21, 0x9d, 0x98, 0x68,
	0xd4, 0xc1, 0x44, 0x17, 0x70, 0x21, 0xa6, 0x71, 0xe9, 0x11, 0x13, 0xdd, 0xca, 0xf1, 0x84, 0x0b,
	0xa1, 0xad, 0x77, 0x57, 0x12, 0x26, 0x1d, 0xfd, 0xd3, 0x18, 0x1d, 0x1d, 0xa5, 0x7f, 0x89, 0xe9,
	0x0f, 0x7e, 0x75, 0x31, 0x71, 0x7a, 0xaf, 0x9f, 0xde, 0xfb, 0xde, 0xf7, 0x7d, 0x73, 0xd0, 0x9b,
	0x08, 0x3d, 0x0d, 0x47, 0x5d, 0xee, 0xcf, 0x2d, 0xee, 0x7b, 0xda, 0x15, 0x1e, 0xca, 0xf1, 0x7e,
	0xeb, 0x06, 0xc2, 0x52, 0x28, 0x17, 0x82, 0xa3, 0xb2, 0xdc, 0x50, 0x4f, 0xad, 0xc5, 0xa5, 0xe5,
	0xce, 0xd4, 0xac, 0x1b, 0x48, 0x5f, 0xfb, 0xb4, 0x94, 0x14, 0xb3, 0x07, 0x30, 0x40, 0xdd, 0xb7,
	0x99, 0xed, 0xe0, 0x1b, 0x6d, 0x40, 0x69, 0xe8, 0xcf, 0xd0, 0x6b, 0x92, 0x36, 0xe9, 0x94, 0x9d,
	0xf4, 0x83, 0x5e, 0x40, 0x79, 0x28, 0xe6, 0xa8, 0xb4, 0x3b, 0x0f, 0x9a, 0x47, 0x6d, 0xd2, 0x29,
	0x3a, 0x3b, 0x60, 0x3e, 0x43, 0x65, 0xab, 0xa0, 0x02, 0xda, 0x86, 0x4a, 0x9f, 0x73, 0x54, 0xca,
	0xc6, 0xe5, 0xc3, 0x38, 0x13, 0xda, 0x47, 0xb4, 0x03, 0x67, 0x0c, 0xb9, 0x44, 0xbd, 0x85, 0x89,
	0x68, 0xd9, 0xc9, 0x63, 0xf3, 0x1d, 0x4e, 0x9f, 0x50, 0x8a, 0xd7, 0xe5, 0xc6, 0xdf, 0xdf, 0xe2,
	0x35, 0x28, 0x3e, 0xaa, 0x49, 0x26, 0x18, 0xb7, 0x87, 0xee, 0x8b, 0x39, 0xf7, 0xf1, 0x5f, 0x26,
	0x26, 0x9e, 0xab, 0x43, 0x89, 0xcd, 0xe3, 0x64, 0x6a, 0x07, 0xcc, 0x1a, 0x54, 0x33, 0x03, 0xcc,
	0x66, 0xf1, 0x7a, 0x57, 0x9f, 0x04, 0x2a, 0x2c, 0x8d, 0xb5, 0x1f, 0xea, 0x29, 0xbd, 0x81, 0xea,
	0x00, 0xf5, 0x86, 0xd8, 0xcc, 0xa6, 0xf5, 0x34, 0xe0, 0xee, 0x2e, 0xd6, 0x16, 0xcd, 0x23, 0x15,
	0xd0, 0x1e, 0xd4, 0x53, 0xe9, 0xfd, 0xd9, 0x46, 0x76, 0xf0, 0x60, 0xeb, 0xd6, 0xf9, 0x21, 0xcd,
	0xac, 0xdc, 0x0f, 0x57, 0x6b, 0xa3, 0xf0, 0xbd, 0x36, 0x0a, 0x1f, 0x91, 0x41, 0x56, 0x91, 0x41,
	0xbe, 0x22, 0x83, 0xfc, 0x44, 0x06, 0x79, 0xb9, 0xfd, 0xd7, 0xeb, 0xb8, 0x8b, 0xeb, 0xe8, 0x24,
	0xb9, 0xeb, 0xfa, 0x37, 0x00, 0x00, 0xff, 0xff, 0x4d, 0x26, 0x81, 0xe6, 0x62, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ServiceAuthClient is the client API for ServiceAuth service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ServiceAuthClient interface {
	GetServiceAKSK(ctx context.Context, in *GetAKSKReq, opts ...grpc.CallOption) (*GetAKSKResp, error)
	VerifyServiceAKSK(ctx context.Context, in *VerifyAKSKReq, opts ...grpc.CallOption) (*VerifyASKSResp, error)
}

type serviceAuthClient struct {
	cc *grpc.ClientConn
}

func NewServiceAuthClient(cc *grpc.ClientConn) ServiceAuthClient {
	return &serviceAuthClient{cc}
}

func (c *serviceAuthClient) GetServiceAKSK(ctx context.Context, in *GetAKSKReq, opts ...grpc.CallOption) (*GetAKSKResp, error) {
	out := new(GetAKSKResp)
	err := c.cc.Invoke(ctx, "/proto.ServiceAuth/GetServiceAKSK", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceAuthClient) VerifyServiceAKSK(ctx context.Context, in *VerifyAKSKReq, opts ...grpc.CallOption) (*VerifyASKSResp, error) {
	out := new(VerifyASKSResp)
	err := c.cc.Invoke(ctx, "/proto.ServiceAuth/VerifyServiceAKSK", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ServiceAuthServer is the server API for ServiceAuth service.
type ServiceAuthServer interface {
	GetServiceAKSK(context.Context, *GetAKSKReq) (*GetAKSKResp, error)
	VerifyServiceAKSK(context.Context, *VerifyAKSKReq) (*VerifyASKSResp, error)
}

// UnimplementedServiceAuthServer can be embedded to have forward compatible implementations.
type UnimplementedServiceAuthServer struct {
}

func (*UnimplementedServiceAuthServer) GetServiceAKSK(ctx context.Context, req *GetAKSKReq) (*GetAKSKResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetServiceAKSK not implemented")
}
func (*UnimplementedServiceAuthServer) VerifyServiceAKSK(ctx context.Context, req *VerifyAKSKReq) (*VerifyASKSResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyServiceAKSK not implemented")
}

func RegisterServiceAuthServer(s *grpc.Server, srv ServiceAuthServer) {
	s.RegisterService(&_ServiceAuth_serviceDesc, srv)
}

func _ServiceAuth_GetServiceAKSK_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAKSKReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceAuthServer).GetServiceAKSK(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.ServiceAuth/GetServiceAKSK",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceAuthServer).GetServiceAKSK(ctx, req.(*GetAKSKReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServiceAuth_VerifyServiceAKSK_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyAKSKReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceAuthServer).VerifyServiceAKSK(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.ServiceAuth/VerifyServiceAKSK",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceAuthServer).VerifyServiceAKSK(ctx, req.(*VerifyAKSKReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _ServiceAuth_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.ServiceAuth",
	HandlerType: (*ServiceAuthServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetServiceAKSK",
			Handler:    _ServiceAuth_GetServiceAKSK_Handler,
		},
		{
			MethodName: "VerifyServiceAKSK",
			Handler:    _ServiceAuth_VerifyServiceAKSK_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "github.com/containerd/containerd/api/services/auth/v1/aksk.proto",
}

func (m *GetAKSKReq) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GetAKSKReq) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GetAKSKReq) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Timestamp != 0 {
		i = encodeVarintAksk(dAtA, i, uint64(m.Timestamp))
		i--
		dAtA[i] = 0x10
	}
	if len(m.Token) > 0 {
		i -= len(m.Token)
		copy(dAtA[i:], m.Token)
		i = encodeVarintAksk(dAtA, i, uint64(len(m.Token)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *GetAKSKResp) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GetAKSKResp) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GetAKSKResp) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.SecretAccessKey) > 0 {
		i -= len(m.SecretAccessKey)
		copy(dAtA[i:], m.SecretAccessKey)
		i = encodeVarintAksk(dAtA, i, uint64(len(m.SecretAccessKey)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.AccessKeyId) > 0 {
		i -= len(m.AccessKeyId)
		copy(dAtA[i:], m.AccessKeyId)
		i = encodeVarintAksk(dAtA, i, uint64(len(m.AccessKeyId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *VerifyAKSKReq) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VerifyAKSKReq) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *VerifyAKSKReq) MarshalToSizedBuffer(dAtA []byte) (int, error) {
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
		i = encodeVarintAksk(dAtA, i, uint64(len(m.Signature)))
		i--
		dAtA[i] = 0x22
	}
	if m.Timestamp != 0 {
		i = encodeVarintAksk(dAtA, i, uint64(m.Timestamp))
		i--
		dAtA[i] = 0x18
	}
	if len(m.Msg) > 0 {
		i -= len(m.Msg)
		copy(dAtA[i:], m.Msg)
		i = encodeVarintAksk(dAtA, i, uint64(len(m.Msg)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.AccessKeyId) > 0 {
		i -= len(m.AccessKeyId)
		copy(dAtA[i:], m.AccessKeyId)
		i = encodeVarintAksk(dAtA, i, uint64(len(m.AccessKeyId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *VerifyASKSResp) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VerifyASKSResp) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *VerifyASKSResp) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	return len(dAtA) - i, nil
}

func encodeVarintAksk(dAtA []byte, offset int, v uint64) int {
	offset -= sovAksk(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *GetAKSKReq) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Token)
	if l > 0 {
		n += 1 + l + sovAksk(uint64(l))
	}
	if m.Timestamp != 0 {
		n += 1 + sovAksk(uint64(m.Timestamp))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *GetAKSKResp) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.AccessKeyId)
	if l > 0 {
		n += 1 + l + sovAksk(uint64(l))
	}
	l = len(m.SecretAccessKey)
	if l > 0 {
		n += 1 + l + sovAksk(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *VerifyAKSKReq) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.AccessKeyId)
	if l > 0 {
		n += 1 + l + sovAksk(uint64(l))
	}
	l = len(m.Msg)
	if l > 0 {
		n += 1 + l + sovAksk(uint64(l))
	}
	if m.Timestamp != 0 {
		n += 1 + sovAksk(uint64(m.Timestamp))
	}
	l = len(m.Signature)
	if l > 0 {
		n += 1 + l + sovAksk(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *VerifyASKSResp) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovAksk(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozAksk(x uint64) (n int) {
	return sovAksk(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *GetAKSKReq) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&GetAKSKReq{`,
		`Token:` + fmt.Sprintf("%v", this.Token) + `,`,
		`Timestamp:` + fmt.Sprintf("%v", this.Timestamp) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *GetAKSKResp) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&GetAKSKResp{`,
		`AccessKeyId:` + fmt.Sprintf("%v", this.AccessKeyId) + `,`,
		`SecretAccessKey:` + fmt.Sprintf("%v", this.SecretAccessKey) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VerifyAKSKReq) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VerifyAKSKReq{`,
		`AccessKeyId:` + fmt.Sprintf("%v", this.AccessKeyId) + `,`,
		`Msg:` + fmt.Sprintf("%v", this.Msg) + `,`,
		`Timestamp:` + fmt.Sprintf("%v", this.Timestamp) + `,`,
		`Signature:` + fmt.Sprintf("%v", this.Signature) + `,`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VerifyASKSResp) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VerifyASKSResp{`,
		`XXX_unrecognized:` + fmt.Sprintf("%v", this.XXX_unrecognized) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringAksk(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *GetAKSKReq) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAksk
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
			return fmt.Errorf("proto: GetAKSKReq: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GetAKSKReq: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Token", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAksk
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
				return ErrInvalidLengthAksk
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAksk
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Token = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			m.Timestamp = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAksk
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
		default:
			iNdEx = preIndex
			skippy, err := skipAksk(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAksk
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
func (m *GetAKSKResp) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAksk
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
			return fmt.Errorf("proto: GetAKSKResp: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GetAKSKResp: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccessKeyId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAksk
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
				return ErrInvalidLengthAksk
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAksk
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccessKeyId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SecretAccessKey", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAksk
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
				return ErrInvalidLengthAksk
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAksk
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SecretAccessKey = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAksk(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAksk
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
func (m *VerifyAKSKReq) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAksk
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
			return fmt.Errorf("proto: VerifyAKSKReq: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VerifyAKSKReq: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccessKeyId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAksk
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
				return ErrInvalidLengthAksk
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAksk
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
					return ErrIntOverflowAksk
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
				return ErrInvalidLengthAksk
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAksk
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
					return ErrIntOverflowAksk
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
					return ErrIntOverflowAksk
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
				return ErrInvalidLengthAksk
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthAksk
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Signature = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAksk(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAksk
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
func (m *VerifyASKSResp) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAksk
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
			return fmt.Errorf("proto: VerifyASKSResp: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VerifyASKSResp: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipAksk(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAksk
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
func skipAksk(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowAksk
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
					return 0, ErrIntOverflowAksk
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
					return 0, ErrIntOverflowAksk
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
				return 0, ErrInvalidLengthAksk
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupAksk
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthAksk
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthAksk        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowAksk          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupAksk = fmt.Errorf("proto: unexpected end of group")
)
