// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/jpittis/netinject/pkg/api/api.proto

package api // import "github.com/jpittis/netinject/pkg/api"

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type Direction int32

const (
	Direction_INBOUND  Direction = 0
	Direction_OUTBOUND Direction = 1
)

var Direction_name = map[int32]string{
	0: "INBOUND",
	1: "OUTBOUND",
}
var Direction_value = map[string]int32{
	"INBOUND":  0,
	"OUTBOUND": 1,
}

func (x Direction) String() string {
	return proto.EnumName(Direction_name, int32(x))
}
func (Direction) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_api_faba1bea98606af2, []int{0}
}

type Update struct {
	Port                 uint32    `protobuf:"varint,1,opt,name=port,proto3" json:"port,omitempty"`
	Direction            Direction `protobuf:"varint,2,opt,name=direction,proto3,enum=netinject.Direction" json:"direction,omitempty"`
	Drop                 bool      `protobuf:"varint,3,opt,name=drop,proto3" json:"drop,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *Update) Reset()         { *m = Update{} }
func (m *Update) String() string { return proto.CompactTextString(m) }
func (*Update) ProtoMessage()    {}
func (*Update) Descriptor() ([]byte, []int) {
	return fileDescriptor_api_faba1bea98606af2, []int{0}
}
func (m *Update) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Update.Unmarshal(m, b)
}
func (m *Update) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Update.Marshal(b, m, deterministic)
}
func (dst *Update) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Update.Merge(dst, src)
}
func (m *Update) XXX_Size() int {
	return xxx_messageInfo_Update.Size(m)
}
func (m *Update) XXX_DiscardUnknown() {
	xxx_messageInfo_Update.DiscardUnknown(m)
}

var xxx_messageInfo_Update proto.InternalMessageInfo

func (m *Update) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Update) GetDirection() Direction {
	if m != nil {
		return m.Direction
	}
	return Direction_INBOUND
}

func (m *Update) GetDrop() bool {
	if m != nil {
		return m.Drop
	}
	return false
}

func init() {
	proto.RegisterType((*Update)(nil), "netinject.Update")
	proto.RegisterEnum("netinject.Direction", Direction_name, Direction_value)
}

func init() {
	proto.RegisterFile("github.com/jpittis/netinject/pkg/api/api.proto", fileDescriptor_api_faba1bea98606af2)
}

var fileDescriptor_api_faba1bea98606af2 = []byte{
	// 187 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x4b, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0xcf, 0x2a, 0xc8, 0x2c, 0x29, 0xc9, 0x2c, 0xd6, 0xcf,
	0x4b, 0x2d, 0xc9, 0xcc, 0xcb, 0x4a, 0x4d, 0x2e, 0xd1, 0x2f, 0xc8, 0x4e, 0xd7, 0x4f, 0x2c, 0xc8,
	0x04, 0x61, 0xbd, 0x82, 0xa2, 0xfc, 0x92, 0x7c, 0x21, 0x4e, 0xb8, 0xa4, 0x52, 0x0a, 0x17, 0x5b,
	0x68, 0x41, 0x4a, 0x62, 0x49, 0xaa, 0x90, 0x10, 0x17, 0x4b, 0x41, 0x7e, 0x51, 0x89, 0x04, 0xa3,
	0x02, 0xa3, 0x06, 0x6f, 0x10, 0x98, 0x2d, 0x64, 0xc4, 0xc5, 0x99, 0x92, 0x59, 0x94, 0x9a, 0x5c,
	0x92, 0x99, 0x9f, 0x27, 0xc1, 0xa4, 0xc0, 0xa8, 0xc1, 0x67, 0x24, 0xa2, 0x07, 0xd7, 0xac, 0xe7,
	0x02, 0x93, 0x0b, 0x42, 0x28, 0x03, 0x99, 0x93, 0x52, 0x94, 0x5f, 0x20, 0xc1, 0xac, 0xc0, 0xa8,
	0xc1, 0x11, 0x04, 0x66, 0x6b, 0xa9, 0x71, 0x71, 0xc2, 0xd5, 0x0a, 0x71, 0x73, 0xb1, 0x7b, 0xfa,
	0x39, 0xf9, 0x87, 0xfa, 0xb9, 0x08, 0x30, 0x08, 0xf1, 0x70, 0x71, 0xf8, 0x87, 0x86, 0x40, 0x78,
	0x8c, 0x4e, 0x6a, 0x51, 0x2a, 0xc4, 0x78, 0x25, 0x89, 0x0d, 0xec, 0x0f, 0x63, 0x40, 0x00, 0x00,
	0x00, 0xff, 0xff, 0xc9, 0xdd, 0x72, 0x4e, 0xf9, 0x00, 0x00, 0x00,
}
