package wotsp

import "encoding/binary"

// Describes a hash address, i.e. where a hash is calculated. It is used to
// randomize each hash function call.
type Address struct {
	data [32]byte
}

func (a *Address) SetLayer(l uint32) {
	binary.BigEndian.PutUint32(a.data[0:], l)
}

func (a *Address) SetTree(t uint64) {
	binary.BigEndian.PutUint64(a.data[4:], t)
}

func (a *Address) SetType(t uint32) {
	binary.BigEndian.PutUint32(a.data[12:], t)
}

func (a *Address) SetOTS(o uint32) {
	binary.BigEndian.PutUint32(a.data[16:], o)
}

func (a *Address) setChain(c uint32) {
	binary.BigEndian.PutUint32(a.data[20:], c)
}

func (a *Address) setHash(h uint32) {
	binary.BigEndian.PutUint32(a.data[24:], h)
}

func (a *Address) setKeyAndMask(km uint32) {
	binary.BigEndian.PutUint32(a.data[28:], km)
}

func (a *Address) ToBytes() []byte {
	return a.data[:]
}
