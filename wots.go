// Implements WOTSP-SHA2_256 as documented in the IETF XMSS draft
// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)
package wotsp

import (
	"encoding/binary"
	"crypto/sha256"
)

const PADDING_F = 0
const PADDING_PRF = 3

const n = 32
const w = 16
const l = 67

type Address struct {
	Layer      uint32	// Index of layer in a tree (0 when not using XMSS)
	Tree       uint64	// Index of tree in a layer (0 when not using XMSS)
	Type       uint32	// Always 0 for W-OTS
	OTS        uint32	// Index of OTS key pair in the tree
	Chain      uint32	// Index of the W-OTS chain
	Hash       uint32	// Index of the hash in a chain
	KeyAndMask uint32	// 0 when generating a key, 1 when generating a bitmask
}

// Returns a byte slice representation of an address
func (a *Address) toBytes() []byte {
	bytes := make([]byte, 32)

	binary.BigEndian.PutUint32(bytes, a.Layer)
	binary.BigEndian.PutUint32(bytes[4:], uint32(a.Tree >> 32))
	binary.BigEndian.PutUint32(bytes[8:], uint32(a.Tree))
	binary.BigEndian.PutUint32(bytes[12:], a.Type)
	binary.BigEndian.PutUint32(bytes[16:], a.OTS)
	binary.BigEndian.PutUint32(bytes[20:], a.Chain)
	binary.BigEndian.PutUint32(bytes[24:], a.Hash)
	binary.BigEndian.PutUint32(bytes[28:], a.KeyAndMask)

	return bytes
}

// Computes the base-16 representation of a binary input.
func base16(x []byte, outlen int) []uint8 {
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

		bits -= 4
		baseW[out] = uint8((total >> bits) & byte(15))
		out++
	}

	return baseW
}

// Generic pad-then-hash function, returns an n-byte slice.
// Input M is padded as (toByte(3, 32) || KEY || M)
func padAndHash(in, key []byte, pad uint16) []byte {
	padding := make([]byte, n)
	binary.BigEndian.PutUint16(padding[n-2:], pad)

	hash := sha256.New()
	hash.Write(padding)
	hash.Write(key)
	hash.Write(in)

	return hash.Sum(nil)
}

// Generates n-byte pseudo random outputs using a 32-byte input and n-byte key.
func prf(in, key []byte) []byte {
	return padAndHash(in, key, PADDING_PRF)
}

// Keyed hash function F using an n-byte input and n-byte key.
func hashF(in, key []byte) []byte {
	return padAndHash(in, key, PADDING_F)
}

// Performs the chaining operation using an n-byte input and n-byte seed.
// Assumes the input is the <start>-th element in the chain, and performs
// <steps> iterations.
func chain(in []byte, start, steps uint32, adrs Address, seed []byte) []byte {
	out := make([]byte, 32)
	copy(out, in)

	for i := start; i < start+steps && i < w; i++ {
		adrs.Hash = i

		adrs.KeyAndMask = 0
		key := prf(adrs.toBytes(), seed)
		adrs.KeyAndMask = 1
		bitmap := prf(adrs.toBytes(), seed)

		for j := 0; j < n; j++ {
			out[j] = out[j] ^ bitmap[j]
		}
		out = hashF(out, key)
	}

	return out
}

// Expands a 32-byte seed into an (l*n)-byte private key.
func expandSeed(seed []byte) []byte {
	privKey := make([]byte, l*n)
	ctr := make([]byte, 32)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		tmp := prf(ctr, seed)
		copy(privKey[i*n:], tmp)
	}

	return privKey
}

// Computes the public key that corresponds to the expanded seed.
func GenPublicKey(adrs Address, seed, pubSeed []byte) []byte {
	privKey := expandSeed(seed)
	pubKey := make([]byte, l*n)

	for i := 0; i < l; i++ {
		adrs.Chain = uint32(i)
		tmp := chain(privKey[i*n:], 0, w-1, adrs, pubSeed)
		copy(pubKey[i*n:], tmp)
	}

	return pubKey
}

// Signs message msg using the private key generated using the given seed.
func Sign(seed uint32, msg []byte) {

}

// Verifies the given signature on the given message.
func Verify(sig, msg []byte) {

}
