// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pkg/security/api/api.proto

package api

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type GetEventParams struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetEventParams) Reset()         { *m = GetEventParams{} }
func (m *GetEventParams) String() string { return proto.CompactTextString(m) }
func (*GetEventParams) ProtoMessage()    {}
func (*GetEventParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{0}
}

func (m *GetEventParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetEventParams.Unmarshal(m, b)
}
func (m *GetEventParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetEventParams.Marshal(b, m, deterministic)
}
func (m *GetEventParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetEventParams.Merge(m, src)
}
func (m *GetEventParams) XXX_Size() int {
	return xxx_messageInfo_GetEventParams.Size(m)
}
func (m *GetEventParams) XXX_DiscardUnknown() {
	xxx_messageInfo_GetEventParams.DiscardUnknown(m)
}

var xxx_messageInfo_GetEventParams proto.InternalMessageInfo

type SecurityEventMessage struct {
	RuleID               string   `protobuf:"bytes,1,opt,name=RuleID,proto3" json:"RuleID,omitempty"`
	Data                 []byte   `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
	Tags                 []string `protobuf:"bytes,3,rep,name=Tags,proto3" json:"Tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecurityEventMessage) Reset()         { *m = SecurityEventMessage{} }
func (m *SecurityEventMessage) String() string { return proto.CompactTextString(m) }
func (*SecurityEventMessage) ProtoMessage()    {}
func (*SecurityEventMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{1}
}

func (m *SecurityEventMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SecurityEventMessage.Unmarshal(m, b)
}
func (m *SecurityEventMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SecurityEventMessage.Marshal(b, m, deterministic)
}
func (m *SecurityEventMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecurityEventMessage.Merge(m, src)
}
func (m *SecurityEventMessage) XXX_Size() int {
	return xxx_messageInfo_SecurityEventMessage.Size(m)
}
func (m *SecurityEventMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_SecurityEventMessage.DiscardUnknown(m)
}

var xxx_messageInfo_SecurityEventMessage proto.InternalMessageInfo

func (m *SecurityEventMessage) GetRuleID() string {
	if m != nil {
		return m.RuleID
	}
	return ""
}

func (m *SecurityEventMessage) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *SecurityEventMessage) GetTags() []string {
	if m != nil {
		return m.Tags
	}
	return nil
}

type DumpProcessCacheParams struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DumpProcessCacheParams) Reset()         { *m = DumpProcessCacheParams{} }
func (m *DumpProcessCacheParams) String() string { return proto.CompactTextString(m) }
func (*DumpProcessCacheParams) ProtoMessage()    {}
func (*DumpProcessCacheParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{2}
}

func (m *DumpProcessCacheParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DumpProcessCacheParams.Unmarshal(m, b)
}
func (m *DumpProcessCacheParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DumpProcessCacheParams.Marshal(b, m, deterministic)
}
func (m *DumpProcessCacheParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DumpProcessCacheParams.Merge(m, src)
}
func (m *DumpProcessCacheParams) XXX_Size() int {
	return xxx_messageInfo_DumpProcessCacheParams.Size(m)
}
func (m *DumpProcessCacheParams) XXX_DiscardUnknown() {
	xxx_messageInfo_DumpProcessCacheParams.DiscardUnknown(m)
}

var xxx_messageInfo_DumpProcessCacheParams proto.InternalMessageInfo

type SecurityDumpProcessCacheMessage struct {
	Filename             string   `protobuf:"bytes,1,opt,name=Filename,proto3" json:"Filename,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecurityDumpProcessCacheMessage) Reset()         { *m = SecurityDumpProcessCacheMessage{} }
func (m *SecurityDumpProcessCacheMessage) String() string { return proto.CompactTextString(m) }
func (*SecurityDumpProcessCacheMessage) ProtoMessage()    {}
func (*SecurityDumpProcessCacheMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{3}
}

func (m *SecurityDumpProcessCacheMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SecurityDumpProcessCacheMessage.Unmarshal(m, b)
}
func (m *SecurityDumpProcessCacheMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SecurityDumpProcessCacheMessage.Marshal(b, m, deterministic)
}
func (m *SecurityDumpProcessCacheMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecurityDumpProcessCacheMessage.Merge(m, src)
}
func (m *SecurityDumpProcessCacheMessage) XXX_Size() int {
	return xxx_messageInfo_SecurityDumpProcessCacheMessage.Size(m)
}
func (m *SecurityDumpProcessCacheMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_SecurityDumpProcessCacheMessage.DiscardUnknown(m)
}

var xxx_messageInfo_SecurityDumpProcessCacheMessage proto.InternalMessageInfo

func (m *SecurityDumpProcessCacheMessage) GetFilename() string {
	if m != nil {
		return m.Filename
	}
	return ""
}

type GetConfigParams struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetConfigParams) Reset()         { *m = GetConfigParams{} }
func (m *GetConfigParams) String() string { return proto.CompactTextString(m) }
func (*GetConfigParams) ProtoMessage()    {}
func (*GetConfigParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{4}
}

func (m *GetConfigParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetConfigParams.Unmarshal(m, b)
}
func (m *GetConfigParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetConfigParams.Marshal(b, m, deterministic)
}
func (m *GetConfigParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetConfigParams.Merge(m, src)
}
func (m *GetConfigParams) XXX_Size() int {
	return xxx_messageInfo_GetConfigParams.Size(m)
}
func (m *GetConfigParams) XXX_DiscardUnknown() {
	xxx_messageInfo_GetConfigParams.DiscardUnknown(m)
}

var xxx_messageInfo_GetConfigParams proto.InternalMessageInfo

type SecurityConfigMessage struct {
	RuntimeEnabled       bool     `protobuf:"varint,1,opt,name=RuntimeEnabled,proto3" json:"RuntimeEnabled,omitempty"`
	FIMEnabled           bool     `protobuf:"varint,2,opt,name=FIMEnabled,proto3" json:"FIMEnabled,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecurityConfigMessage) Reset()         { *m = SecurityConfigMessage{} }
func (m *SecurityConfigMessage) String() string { return proto.CompactTextString(m) }
func (*SecurityConfigMessage) ProtoMessage()    {}
func (*SecurityConfigMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{5}
}

func (m *SecurityConfigMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SecurityConfigMessage.Unmarshal(m, b)
}
func (m *SecurityConfigMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SecurityConfigMessage.Marshal(b, m, deterministic)
}
func (m *SecurityConfigMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecurityConfigMessage.Merge(m, src)
}
func (m *SecurityConfigMessage) XXX_Size() int {
	return xxx_messageInfo_SecurityConfigMessage.Size(m)
}
func (m *SecurityConfigMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_SecurityConfigMessage.DiscardUnknown(m)
}

var xxx_messageInfo_SecurityConfigMessage proto.InternalMessageInfo

func (m *SecurityConfigMessage) GetRuntimeEnabled() bool {
	if m != nil {
		return m.RuntimeEnabled
	}
	return false
}

func (m *SecurityConfigMessage) GetFIMEnabled() bool {
	if m != nil {
		return m.FIMEnabled
	}
	return false
}

type RunSelfTestParams struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RunSelfTestParams) Reset()         { *m = RunSelfTestParams{} }
func (m *RunSelfTestParams) String() string { return proto.CompactTextString(m) }
func (*RunSelfTestParams) ProtoMessage()    {}
func (*RunSelfTestParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{6}
}

func (m *RunSelfTestParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RunSelfTestParams.Unmarshal(m, b)
}
func (m *RunSelfTestParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RunSelfTestParams.Marshal(b, m, deterministic)
}
func (m *RunSelfTestParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RunSelfTestParams.Merge(m, src)
}
func (m *RunSelfTestParams) XXX_Size() int {
	return xxx_messageInfo_RunSelfTestParams.Size(m)
}
func (m *RunSelfTestParams) XXX_DiscardUnknown() {
	xxx_messageInfo_RunSelfTestParams.DiscardUnknown(m)
}

var xxx_messageInfo_RunSelfTestParams proto.InternalMessageInfo

type SecuritySelfTestResultMessage struct {
	Ok                   bool     `protobuf:"varint,1,opt,name=Ok,proto3" json:"Ok,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SecuritySelfTestResultMessage) Reset()         { *m = SecuritySelfTestResultMessage{} }
func (m *SecuritySelfTestResultMessage) String() string { return proto.CompactTextString(m) }
func (*SecuritySelfTestResultMessage) ProtoMessage()    {}
func (*SecuritySelfTestResultMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_ce049ba84fb5261a, []int{7}
}

func (m *SecuritySelfTestResultMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SecuritySelfTestResultMessage.Unmarshal(m, b)
}
func (m *SecuritySelfTestResultMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SecuritySelfTestResultMessage.Marshal(b, m, deterministic)
}
func (m *SecuritySelfTestResultMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SecuritySelfTestResultMessage.Merge(m, src)
}
func (m *SecuritySelfTestResultMessage) XXX_Size() int {
	return xxx_messageInfo_SecuritySelfTestResultMessage.Size(m)
}
func (m *SecuritySelfTestResultMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_SecuritySelfTestResultMessage.DiscardUnknown(m)
}

var xxx_messageInfo_SecuritySelfTestResultMessage proto.InternalMessageInfo

func (m *SecuritySelfTestResultMessage) GetOk() bool {
	if m != nil {
		return m.Ok
	}
	return false
}

func init() {
	proto.RegisterType((*GetEventParams)(nil), "api.GetEventParams")
	proto.RegisterType((*SecurityEventMessage)(nil), "api.SecurityEventMessage")
	proto.RegisterType((*DumpProcessCacheParams)(nil), "api.DumpProcessCacheParams")
	proto.RegisterType((*SecurityDumpProcessCacheMessage)(nil), "api.SecurityDumpProcessCacheMessage")
	proto.RegisterType((*GetConfigParams)(nil), "api.GetConfigParams")
	proto.RegisterType((*SecurityConfigMessage)(nil), "api.SecurityConfigMessage")
	proto.RegisterType((*RunSelfTestParams)(nil), "api.RunSelfTestParams")
	proto.RegisterType((*SecuritySelfTestResultMessage)(nil), "api.SecuritySelfTestResultMessage")
}

func init() { proto.RegisterFile("pkg/security/api/api.proto", fileDescriptor_ce049ba84fb5261a) }

var fileDescriptor_ce049ba84fb5261a = []byte{
	// 383 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x92, 0x5f, 0x6b, 0xe2, 0x40,
	0x14, 0xc5, 0x93, 0xb8, 0x88, 0xde, 0x5d, 0xb2, 0x3a, 0xba, 0x92, 0xcd, 0xb2, 0xbb, 0x32, 0x2c,
	0x8b, 0x4f, 0x5a, 0xda, 0xe7, 0x52, 0xa8, 0xff, 0x90, 0x22, 0xca, 0x28, 0x2d, 0xf4, 0xa5, 0x8c,
	0x7a, 0x4d, 0x83, 0xf9, 0x47, 0x26, 0x29, 0xf4, 0x9b, 0xf5, 0xe3, 0x15, 0xc7, 0x8c, 0x98, 0xd4,
	0x3e, 0x04, 0x66, 0x4e, 0xee, 0x9c, 0x33, 0xfc, 0xce, 0x80, 0x1d, 0xed, 0x9c, 0x9e, 0xc0, 0x75,
	0x1a, 0xbb, 0xc9, 0x6b, 0x8f, 0x47, 0xee, 0xfe, 0xeb, 0x46, 0x71, 0x98, 0x84, 0xa4, 0xc4, 0x23,
	0x97, 0xd6, 0xc0, 0x1c, 0x63, 0x32, 0x7c, 0xc1, 0x20, 0x99, 0xf3, 0x98, 0xfb, 0x82, 0xde, 0x43,
	0x73, 0x91, 0x1d, 0x90, 0xf2, 0x14, 0x85, 0xe0, 0x0e, 0x92, 0x16, 0x94, 0x59, 0xea, 0xe1, 0x64,
	0x60, 0xe9, 0x6d, 0xbd, 0x53, 0x65, 0xd9, 0x8e, 0x10, 0xf8, 0x32, 0xe0, 0x09, 0xb7, 0x8c, 0xb6,
	0xde, 0xf9, 0xc6, 0xe4, 0x7a, 0xaf, 0x2d, 0xb9, 0x23, 0xac, 0x52, 0xbb, 0xd4, 0xa9, 0x32, 0xb9,
	0xa6, 0x16, 0xb4, 0x06, 0xa9, 0x1f, 0xcd, 0xe3, 0x70, 0x8d, 0x42, 0xf4, 0xf9, 0xfa, 0x19, 0xb3,
	0xc4, 0x6b, 0xf8, 0xab, 0x12, 0x8b, 0x13, 0x2a, 0xdc, 0x86, 0xca, 0xc8, 0xf5, 0x30, 0xe0, 0x3e,
	0x66, 0xf1, 0xc7, 0x3d, 0xad, 0xc3, 0xf7, 0x31, 0x26, 0xfd, 0x30, 0xd8, 0xba, 0x4e, 0xe6, 0xf8,
	0x04, 0x3f, 0x94, 0xe3, 0x41, 0x57, 0x3e, 0xff, 0xc1, 0x64, 0x69, 0x90, 0xb8, 0x3e, 0x0e, 0x03,
	0xbe, 0xf2, 0x70, 0x23, 0xdd, 0x2a, 0xac, 0xa0, 0x92, 0x3f, 0x00, 0xa3, 0xc9, 0x54, 0xcd, 0x18,
	0x72, 0xe6, 0x44, 0xa1, 0x0d, 0xa8, 0xb3, 0x34, 0x58, 0xa0, 0xb7, 0x5d, 0xa2, 0x50, 0xe4, 0x7a,
	0xf0, 0x5b, 0xa5, 0xaa, 0x3f, 0x0c, 0x45, 0xea, 0x1d, 0x11, 0x9a, 0x60, 0xcc, 0x76, 0x59, 0xa2,
	0x31, 0xdb, 0x5d, 0xbe, 0x19, 0x60, 0xaa, 0x13, 0xd3, 0x70, 0x93, 0x7a, 0x48, 0x6e, 0xa0, 0xaa,
	0xfa, 0x10, 0xa4, 0xd1, 0xdd, 0xb7, 0x95, 0xef, 0xc7, 0xfe, 0x29, 0xc5, 0x73, 0x15, 0x51, 0xed,
	0x42, 0x27, 0x0f, 0x50, 0x2b, 0x42, 0x24, 0xbf, 0xe4, 0x91, 0xf3, 0xf4, 0xed, 0x7f, 0x39, 0xbf,
	0x4f, 0x0a, 0xa0, 0x5a, 0x76, 0xb3, 0x03, 0x4e, 0xd2, 0x54, 0x37, 0x3b, 0xc5, 0x6e, 0xdb, 0x39,
	0xab, 0x1c, 0x79, 0xaa, 0x91, 0x3b, 0xf8, 0x7a, 0xc2, 0x8c, 0xb4, 0xe4, 0xf0, 0x07, 0x8a, 0x36,
	0xcd, 0x99, 0x9c, 0x05, 0x49, 0xb5, 0x5b, 0xf2, 0x58, 0x2b, 0x3e, 0xed, 0x55, 0x59, 0xbe, 0xeb,
	0xab, 0xf7, 0x00, 0x00, 0x00, 0xff, 0xff, 0x3d, 0xd7, 0x94, 0x2e, 0xf5, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// SecurityModuleClient is the client API for SecurityModule service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type SecurityModuleClient interface {
	GetEvents(ctx context.Context, in *GetEventParams, opts ...grpc.CallOption) (SecurityModule_GetEventsClient, error)
	DumpProcessCache(ctx context.Context, in *DumpProcessCacheParams, opts ...grpc.CallOption) (*SecurityDumpProcessCacheMessage, error)
	GetConfig(ctx context.Context, in *GetConfigParams, opts ...grpc.CallOption) (*SecurityConfigMessage, error)
	RunSelfTest(ctx context.Context, in *RunSelfTestParams, opts ...grpc.CallOption) (*SecuritySelfTestResultMessage, error)
}

type securityModuleClient struct {
	cc *grpc.ClientConn
}

func NewSecurityModuleClient(cc *grpc.ClientConn) SecurityModuleClient {
	return &securityModuleClient{cc}
}

func (c *securityModuleClient) GetEvents(ctx context.Context, in *GetEventParams, opts ...grpc.CallOption) (SecurityModule_GetEventsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_SecurityModule_serviceDesc.Streams[0], "/api.SecurityModule/GetEvents", opts...)
	if err != nil {
		return nil, err
	}
	x := &securityModuleGetEventsClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type SecurityModule_GetEventsClient interface {
	Recv() (*SecurityEventMessage, error)
	grpc.ClientStream
}

type securityModuleGetEventsClient struct {
	grpc.ClientStream
}

func (x *securityModuleGetEventsClient) Recv() (*SecurityEventMessage, error) {
	m := new(SecurityEventMessage)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *securityModuleClient) DumpProcessCache(ctx context.Context, in *DumpProcessCacheParams, opts ...grpc.CallOption) (*SecurityDumpProcessCacheMessage, error) {
	out := new(SecurityDumpProcessCacheMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/DumpProcessCache", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) GetConfig(ctx context.Context, in *GetConfigParams, opts ...grpc.CallOption) (*SecurityConfigMessage, error) {
	out := new(SecurityConfigMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/GetConfig", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *securityModuleClient) RunSelfTest(ctx context.Context, in *RunSelfTestParams, opts ...grpc.CallOption) (*SecuritySelfTestResultMessage, error) {
	out := new(SecuritySelfTestResultMessage)
	err := c.cc.Invoke(ctx, "/api.SecurityModule/RunSelfTest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SecurityModuleServer is the server API for SecurityModule service.
type SecurityModuleServer interface {
	GetEvents(*GetEventParams, SecurityModule_GetEventsServer) error
	DumpProcessCache(context.Context, *DumpProcessCacheParams) (*SecurityDumpProcessCacheMessage, error)
	GetConfig(context.Context, *GetConfigParams) (*SecurityConfigMessage, error)
	RunSelfTest(context.Context, *RunSelfTestParams) (*SecuritySelfTestResultMessage, error)
}

// UnimplementedSecurityModuleServer can be embedded to have forward compatible implementations.
type UnimplementedSecurityModuleServer struct {
}

func (*UnimplementedSecurityModuleServer) GetEvents(req *GetEventParams, srv SecurityModule_GetEventsServer) error {
	return status.Errorf(codes.Unimplemented, "method GetEvents not implemented")
}
func (*UnimplementedSecurityModuleServer) DumpProcessCache(ctx context.Context, req *DumpProcessCacheParams) (*SecurityDumpProcessCacheMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DumpProcessCache not implemented")
}
func (*UnimplementedSecurityModuleServer) GetConfig(ctx context.Context, req *GetConfigParams) (*SecurityConfigMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfig not implemented")
}
func (*UnimplementedSecurityModuleServer) RunSelfTest(ctx context.Context, req *RunSelfTestParams) (*SecuritySelfTestResultMessage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RunSelfTest not implemented")
}

func RegisterSecurityModuleServer(s *grpc.Server, srv SecurityModuleServer) {
	s.RegisterService(&_SecurityModule_serviceDesc, srv)
}

func _SecurityModule_GetEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetEventParams)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SecurityModuleServer).GetEvents(m, &securityModuleGetEventsServer{stream})
}

type SecurityModule_GetEventsServer interface {
	Send(*SecurityEventMessage) error
	grpc.ServerStream
}

type securityModuleGetEventsServer struct {
	grpc.ServerStream
}

func (x *securityModuleGetEventsServer) Send(m *SecurityEventMessage) error {
	return x.ServerStream.SendMsg(m)
}

func _SecurityModule_DumpProcessCache_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DumpProcessCacheParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).DumpProcessCache(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/DumpProcessCache",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).DumpProcessCache(ctx, req.(*DumpProcessCacheParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_GetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetConfigParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).GetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/GetConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).GetConfig(ctx, req.(*GetConfigParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _SecurityModule_RunSelfTest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RunSelfTestParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SecurityModuleServer).RunSelfTest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.SecurityModule/RunSelfTest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SecurityModuleServer).RunSelfTest(ctx, req.(*RunSelfTestParams))
	}
	return interceptor(ctx, in, info, handler)
}

var _SecurityModule_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.SecurityModule",
	HandlerType: (*SecurityModuleServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DumpProcessCache",
			Handler:    _SecurityModule_DumpProcessCache_Handler,
		},
		{
			MethodName: "GetConfig",
			Handler:    _SecurityModule_GetConfig_Handler,
		},
		{
			MethodName: "RunSelfTest",
			Handler:    _SecurityModule_RunSelfTest_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetEvents",
			Handler:       _SecurityModule_GetEvents_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "pkg/security/api/api.proto",
}
