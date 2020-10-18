// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: errdefs.proto

package errdefs

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	pb "github.com/moby/buildkit/solver/pb"
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
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Vertex struct {
	Digest               string   `protobuf:"bytes,1,opt,name=digest,proto3" json:"digest,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Vertex) Reset()         { *m = Vertex{} }
func (m *Vertex) String() string { return proto.CompactTextString(m) }
func (*Vertex) ProtoMessage()    {}
func (*Vertex) Descriptor() ([]byte, []int) {
	return fileDescriptor_689dc58a5060aff5, []int{0}
}
func (m *Vertex) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Vertex.Unmarshal(m, b)
}
func (m *Vertex) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Vertex.Marshal(b, m, deterministic)
}
func (m *Vertex) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Vertex.Merge(m, src)
}
func (m *Vertex) XXX_Size() int {
	return xxx_messageInfo_Vertex.Size(m)
}
func (m *Vertex) XXX_DiscardUnknown() {
	xxx_messageInfo_Vertex.DiscardUnknown(m)
}

var xxx_messageInfo_Vertex proto.InternalMessageInfo

func (m *Vertex) GetDigest() string {
	if m != nil {
		return m.Digest
	}
	return ""
}

type Source struct {
	Info                 *pb.SourceInfo `protobuf:"bytes,1,opt,name=info,proto3" json:"info,omitempty"`
	Ranges               []*pb.Range    `protobuf:"bytes,2,rep,name=ranges,proto3" json:"ranges,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Source) Reset()         { *m = Source{} }
func (m *Source) String() string { return proto.CompactTextString(m) }
func (*Source) ProtoMessage()    {}
func (*Source) Descriptor() ([]byte, []int) {
	return fileDescriptor_689dc58a5060aff5, []int{1}
}
func (m *Source) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Source.Unmarshal(m, b)
}
func (m *Source) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Source.Marshal(b, m, deterministic)
}
func (m *Source) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Source.Merge(m, src)
}
func (m *Source) XXX_Size() int {
	return xxx_messageInfo_Source.Size(m)
}
func (m *Source) XXX_DiscardUnknown() {
	xxx_messageInfo_Source.DiscardUnknown(m)
}

var xxx_messageInfo_Source proto.InternalMessageInfo

func (m *Source) GetInfo() *pb.SourceInfo {
	if m != nil {
		return m.Info
	}
	return nil
}

func (m *Source) GetRanges() []*pb.Range {
	if m != nil {
		return m.Ranges
	}
	return nil
}

type FrontendCap struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FrontendCap) Reset()         { *m = FrontendCap{} }
func (m *FrontendCap) String() string { return proto.CompactTextString(m) }
func (*FrontendCap) ProtoMessage()    {}
func (*FrontendCap) Descriptor() ([]byte, []int) {
	return fileDescriptor_689dc58a5060aff5, []int{2}
}
func (m *FrontendCap) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FrontendCap.Unmarshal(m, b)
}
func (m *FrontendCap) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FrontendCap.Marshal(b, m, deterministic)
}
func (m *FrontendCap) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FrontendCap.Merge(m, src)
}
func (m *FrontendCap) XXX_Size() int {
	return xxx_messageInfo_FrontendCap.Size(m)
}
func (m *FrontendCap) XXX_DiscardUnknown() {
	xxx_messageInfo_FrontendCap.DiscardUnknown(m)
}

var xxx_messageInfo_FrontendCap proto.InternalMessageInfo

func (m *FrontendCap) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type Subrequest struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Subrequest) Reset()         { *m = Subrequest{} }
func (m *Subrequest) String() string { return proto.CompactTextString(m) }
func (*Subrequest) ProtoMessage()    {}
func (*Subrequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_689dc58a5060aff5, []int{3}
}
func (m *Subrequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Subrequest.Unmarshal(m, b)
}
func (m *Subrequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Subrequest.Marshal(b, m, deterministic)
}
func (m *Subrequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Subrequest.Merge(m, src)
}
func (m *Subrequest) XXX_Size() int {
	return xxx_messageInfo_Subrequest.Size(m)
}
func (m *Subrequest) XXX_DiscardUnknown() {
	xxx_messageInfo_Subrequest.DiscardUnknown(m)
}

var xxx_messageInfo_Subrequest proto.InternalMessageInfo

func (m *Subrequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func init() {
	proto.RegisterType((*Vertex)(nil), "errdefs.Vertex")
	proto.RegisterType((*Source)(nil), "errdefs.Source")
	proto.RegisterType((*FrontendCap)(nil), "errdefs.FrontendCap")
	proto.RegisterType((*Subrequest)(nil), "errdefs.Subrequest")
}

func init() { proto.RegisterFile("errdefs.proto", fileDescriptor_689dc58a5060aff5) }

var fileDescriptor_689dc58a5060aff5 = []byte{
	// 213 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x8e, 0xc1, 0x4a, 0x03, 0x31,
	0x10, 0x86, 0xa9, 0x96, 0x48, 0x67, 0xd1, 0x43, 0x0e, 0x52, 0x3c, 0x6d, 0x73, 0xea, 0x41, 0x36,
	0x50, 0x1f, 0x41, 0x10, 0x3c, 0x09, 0x5b, 0xf0, 0xbe, 0x69, 0x66, 0xd7, 0x60, 0x37, 0x13, 0x27,
	0x89, 0xe8, 0xdb, 0xcb, 0xc6, 0x1c, 0x7b, 0x9b, 0x7f, 0xbe, 0x6f, 0x98, 0x1f, 0x6e, 0x91, 0xd9,
	0xe2, 0x18, 0xbb, 0xc0, 0x94, 0x48, 0xde, 0xd4, 0xf8, 0xf0, 0x38, 0xb9, 0xf4, 0x91, 0x4d, 0x77,
	0xa2, 0x59, 0xcf, 0x64, 0x7e, 0xb5, 0xc9, 0xee, 0x6c, 0x3f, 0x5d, 0xd2, 0x91, 0xce, 0xdf, 0xc8,
	0x3a, 0x18, 0x4d, 0xa1, 0x9e, 0xa9, 0x16, 0xc4, 0x3b, 0x72, 0xc2, 0x1f, 0x79, 0x0f, 0xc2, 0xba,
	0x09, 0x63, 0xda, 0xae, 0xda, 0xd5, 0x7e, 0xd3, 0xd7, 0xa4, 0xde, 0x40, 0x1c, 0x29, 0xf3, 0x09,
	0xa5, 0x82, 0xb5, 0xf3, 0x23, 0x15, 0xde, 0x1c, 0xee, 0xba, 0x60, 0xba, 0x7f, 0xf2, 0xea, 0x47,
	0xea, 0x0b, 0x93, 0x3b, 0x10, 0x3c, 0xf8, 0x09, 0xe3, 0xf6, 0xaa, 0xbd, 0xde, 0x37, 0x87, 0xcd,
	0x62, 0xf5, 0xcb, 0xa6, 0xaf, 0x40, 0xed, 0xa0, 0x79, 0x61, 0xf2, 0x09, 0xbd, 0x7d, 0x1e, 0x82,
	0x94, 0xb0, 0xf6, 0xc3, 0x8c, 0xf5, 0x6b, 0x99, 0x55, 0x0b, 0x70, 0xcc, 0x86, 0xf1, 0x2b, 0x63,
	0x4c, 0x97, 0x0c, 0x23, 0x4a, 0xfd, 0xa7, 0xbf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x75, 0x4b, 0xfe,
	0xad, 0x06, 0x01, 0x00, 0x00,
}