// Code generated by protoc-gen-go.
// source: primitives.proto
// DO NOT EDIT!

package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type CSR struct {
	Der []byte `protobuf:"bytes,1,opt,name=der,proto3" json:"der,omitempty"`
}

func (m *CSR) Reset()                    { *m = CSR{} }
func (m *CSR) String() string            { return proto.CompactTextString(m) }
func (*CSR) ProtoMessage()               {}
func (*CSR) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{0} }

func (m *CSR) GetDer() []byte {
	if m != nil {
		return m.Der
	}
	return nil
}

type Certificate struct {
	Der []byte `protobuf:"bytes,1,opt,name=der,proto3" json:"der,omitempty"`
}

func (m *Certificate) Reset()                    { *m = Certificate{} }
func (m *Certificate) String() string            { return proto.CompactTextString(m) }
func (*Certificate) ProtoMessage()               {}
func (*Certificate) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{1} }

func (m *Certificate) GetDer() []byte {
	if m != nil {
		return m.Der
	}
	return nil
}

func init() {
	proto.RegisterType((*CSR)(nil), "cybercom.CSR")
	proto.RegisterType((*Certificate)(nil), "cybercom.Certificate")
}

func init() { proto.RegisterFile("primitives.proto", fileDescriptor1) }

var fileDescriptor1 = []byte{
	// 103 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0x12, 0x28, 0x28, 0xca, 0xcc,
	0xcd, 0x2c, 0xc9, 0x2c, 0x4b, 0x2d, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x48, 0xae,
	0x4c, 0x4a, 0x2d, 0x4a, 0xce, 0xcf, 0x55, 0x12, 0xe7, 0x62, 0x76, 0x0e, 0x0e, 0x12, 0x12, 0xe0,
	0x62, 0x4e, 0x49, 0x2d, 0x92, 0x60, 0x54, 0x60, 0xd4, 0xe0, 0x09, 0x02, 0x31, 0x95, 0xe4, 0xb9,
	0xb8, 0x9d, 0x53, 0x8b, 0x4a, 0x32, 0xd3, 0x32, 0x93, 0x13, 0x4b, 0x52, 0x31, 0x15, 0x38, 0xb1,
	0x44, 0x31, 0x15, 0x24, 0x25, 0xb1, 0x81, 0x0d, 0x34, 0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0xd8,
	0xef, 0xd3, 0xc4, 0x64, 0x00, 0x00, 0x00,
}