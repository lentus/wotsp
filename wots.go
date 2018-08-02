// Implements WOTSP-SHA2_256 as documented in RFC 8391
// (https://datatracker.ietf.org/doc/rfc8391/)
package wotsp

import (
	"encoding/binary"
	"bytes"
)

const n = 32
var w = uint8(16)
var logW = uint(4)
var l1 = 64
var l2 = 3
var l = l1 + l2

type Mode int
const (
	W4 Mode = iota
	W16
)

// Sets all internal parameters according to the given mode of operation. The
// available parameter sets include w = 4 and w = 16. The default, which is used
// when this function is not called, is w = 16. See RFC 8391 for details on the
// different parameter sets.
func SetMode(m Mode) {
	switch m {
	case W4:
		w = uint8(4)
		logW = uint(2)
		l1 = 128
		l2 = 5
	case W16:
	default:
		w = uint8(16)
		logW = uint(4)
		l1 = 64
		l2 = 3
	}

	l = l1+l2
}

// Computes the base-16 representation of a binary input.
func baseW(x []byte, outlen int) []uint8 {
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

		bits -= logW
		baseW[out] = uint8((total >> bits) & byte(w-1))
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
func chain(h *hasher, scratch, in, out []byte, start, steps uint8, adrs *Address) {
	copy(out, in)

	for i := start; i < start+steps && i < w; i++ {
		adrs.setHash(uint32(i))

		adrs.setKeyAndMask(0)
		h.prfPubSeed(adrs, scratch[:32])
		adrs.setKeyAndMask(1)
		h.prfPubSeed(adrs, scratch[32:64])

		for j := 0; j < n; j++ {
			out[j] = out[j] ^ scratch[32+j]
		}

		h.hashF(scratch[:32], out)
	}
}

// Expands a 32-byte seed into an (l*n)-byte private key.
func expandSeed(h *hasher) []byte {
	privKey := make([]byte, l*n)
	ctr := make([]byte, 32)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		h.prfPrivSeed(ctr, privKey[i*n:])
	}

	return privKey
}

// Computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed, pubSeed []byte, adrs *Address) []byte {
	h := precompute(seed, pubSeed)

	privKey := expandSeed(h)
	scratch := make([]byte, 64)

	pubKey := make([]byte, l*n)
	for i := 0; i < l; i++ {
		adrs.setChain(uint32(i))
		chain(h, scratch, privKey[i*n:], pubKey[i*n:(i+1)*n], 0, w-1, adrs)
	}

	return pubKey
}

func checksum(msg []uint8) []uint8 {
	csum := uint32(0)
	for i := 0; i < l1; i++ {
		csum += uint32(w - 1 - msg[i])
	}
	csum <<= 8 - ((uint(l2) * logW) % 8)

	// Length of the checksum is (l2*logw + 7) / 8
	csumBytes := make([]byte, 2)
	// Since bytesLen is always 2, we can truncate csum to a uint16.
	binary.BigEndian.PutUint16(csumBytes, uint16(csum))

	return baseW(csumBytes, l2)
}

// Signs message msg using the private key generated using the given seed.
func Sign(msg, seed, pubSeed []byte, adrs *Address) []byte {
	h := precompute(seed, pubSeed)

	privKey := expandSeed(h)
	lengths := baseW(msg, l1)
	scratch := make([]byte, 64)

	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	sig := make([]byte, l*n)
	for i := 0; i < l; i++ {
		adrs.setChain(uint32(i))
		chain(h, scratch, privKey[i*n:], sig[i*n:(i+1)*n], 0, lengths[i], adrs)
	}

	return sig
}

// Generates a public key from the given signature
func PkFromSig(sig, msg, pubSeed []byte, adrs *Address) []byte {
	h := precompute(nil, pubSeed)

	lengths := baseW(msg, l1)
	scratch := make([]byte, 64)

	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	pubKey := make([]byte, l*n)
	for i := 0; i < l; i++ {
		adrs.setChain(uint32(i))
		chain(h, scratch, sig[i*n:], pubKey[i*n:(i+1)*n], lengths[i], w-1-lengths[i], adrs)
	}

	return pubKey
}

// Verifies the given signature on the given message.
func Verify(pk, sig, msg, pubSeed []byte, adrs *Address) bool {
	return bytes.Equal(pk, PkFromSig(sig, msg, pubSeed, adrs))
}
