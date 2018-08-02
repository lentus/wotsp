package wotsp

import (
	"crypto"
	"encoding/binary"
)

// Opts groups the parameters required for WOTSP operations.
//
// Opts implements crypto.SignerOpts and crypto.DecrypterOpts.
type Opts struct {
	Mode    Mode
	PubSeed []byte
	Address Address
}

// mode should implement crypto.SignerOpts
var _ crypto.SignerOpts = Opts{}

// HashFunc implements crypto.SignerOpts.
//
// WOTS uses SHA256 as its internal hash function, so HashFunc will always
// return crypto.SHA256.
func (Opts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// params is an internal struct that defines parameters that specify a "Mode" in
// WOTS.
type params struct {
	w         uint8
	logW      uint
	l1, l2, l int
}

// Computes the base-16 representation of a binary input.
func (p params) baseW(x []byte, outlen int) []uint8 {
	var total byte
	in := 0
	out := 0
	bits := uint(0)
	baseW := make([]uint8, outlen)

	for consumed := 0; consumed < outlen; consumed++ {
		if bits == 0 {
			total = x[in]
			in++
			bits += 8
		}

		bits -= p.logW
		baseW[out] = uint8((total >> bits) & byte(p.w-1))
		out++
	}

	return baseW
}

// Performs the chaining operation using an n-byte input and n-byte seed.
// Assumes the input is the <start>-th element in the chain, and performs
// <steps> iterations.
//
// Scratch is used as a scratch pad: it is pre-allocated to prevent every call
// to chain from allocating slices for keys and bitmask. It is used as:
// 		scratch = key || bitmask.
func (p params) chain(h *hasher, scratch, in, out []byte, start, steps uint8, adrs *Address) {
	copy(out, in)

	for i := start; i < start+steps && i < p.w; i++ {
		adrs.setHash(uint32(i))

		adrs.setKeyAndMask(0)
		h.prfPubSeed(adrs, scratch[:32])
		adrs.setKeyAndMask(1)
		h.prfPubSeed(adrs, scratch[32:64])

		for j := 0; j < N; j++ {
			out[j] = out[j] ^ scratch[32+j]
		}

		h.hashF(scratch[:32], out)
	}
}

// Expands a 32-byte seed into an (l*n)-byte private key.
func (p params) expandSeed(h *hasher) []byte {
	privKey := make([]byte, p.l*N)
	ctr := make([]byte, 32)

	for i := 0; i < p.l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		h.prfPrivSeed(ctr, privKey[i*N:])
	}

	return privKey
}

func (p params) checksum(msg []uint8) []uint8 {
	csum := uint32(0)
	for i := 0; i < p.l1; i++ {
		csum += uint32(p.w - 1 - msg[i])
	}
	csum <<= 8 - ((uint(p.l2) * p.logW) % 8)

	// Length of the checksum is (l2*logw + 7) / 8
	csumBytes := make([]byte, 2)
	// Since bytesLen is always 2, we can truncate csum to a uint16.
	binary.BigEndian.PutUint16(csumBytes, uint16(csum))

	return p.baseW(csumBytes, p.l2)
}
