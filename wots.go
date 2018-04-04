// Implements WOTSP-SHA2_256 as documented in the IETF XMSS draft
// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)
package wotsp

import (
	"encoding/binary"
	"crypto/sha256"
	"bytes"
)

const paddingF = 0
const paddingPrf = 3

const n = 32
const w = 16
const l1 = 64
const l2 = 3
const l = l1 + l2

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

func (a *Address) SetChain(c uint32) {
	binary.BigEndian.PutUint32(a.data[20:], c)
}

func (a *Address) SetHash(h uint32) {
	binary.BigEndian.PutUint32(a.data[24:], h)
}

func (a *Address) SetKeyAndMask(km uint32) {
	binary.BigEndian.PutUint32(a.data[28:], km)
}

func (a *Address) toBytes() []byte {
	return a.data[:]
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
	return padAndHash(in, key, paddingPrf)
}

// Keyed hash function F using an n-byte input and n-byte key.
func hashF(in, key []byte) []byte {
	return padAndHash(in, key, paddingF)
}

// Performs the chaining operation using an n-byte input and n-byte seed.
// Assumes the input is the <start>-th element in the chain, and performs
// <steps> iterations.
func chain(in []byte, start, steps uint8, adrs Address, seed []byte) []byte {
	out := make([]byte, 32)
	copy(out, in)

	for i := start; i < start+steps && i < w; i++ {
		adrs.SetHash(uint32(i))

		adrs.SetKeyAndMask(0)
		key := prf(adrs.toBytes(), seed)
		adrs.SetKeyAndMask(1)
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
func GenPublicKey(seed, pubSeed []byte, adrs Address) []byte {
	privKey := expandSeed(seed)
	pubKey := make([]byte, l*n)

	for i := 0; i < l; i++ {
		adrs.SetChain(uint32(i))
		tmp := chain(privKey[i*n:], 0, w-1, adrs, pubSeed)
		copy(pubKey[i*n:], tmp)
	}

	return pubKey
}

func checksum(msg []uint8) []uint8 {
	csum := uint32(0)
	for i := 0; i < l1; i++ {
		csum += uint32(w - 1 - msg[i])
	}
	csum <<= 4 // 8 - ((l2 * logw) % 8)

	// Length of the checksum is (l2*logw + 7) / 8
	csumBytes := make([]byte, 2)
	// Since bytesLen is always 2, we can truncate csum to a uint16.
	binary.BigEndian.PutUint16(csumBytes, uint16(csum))

	return base16(csumBytes, l2)
}

// Signs message msg using the private key generated using the given seed.
func Sign(msg, seed, pubSeed []byte, adrs Address) []byte {
	privKey := expandSeed(seed)
	lengths := base16(msg, l1)

	// Compute checksum
	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	// Compute signature
	sig := make([]byte, l*n)
	for i := 0; i < l; i++ {
		adrs.SetChain(uint32(i))
		tmp := chain(privKey[i*n:], 0, lengths[i], adrs, pubSeed)
		copy(sig[i*n:], tmp)
	}

	return sig
}

// Generates a public key from the given signature
func PkFromSig(sig, msg, pubSeed []byte, adrs Address) []byte {
	lengths := base16(msg, l1)

	// Compute checksum
	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	// Compute public key
	pubKey := make([]byte, l*n)
	for i := 0; i < l; i++ {
		adrs.SetChain(uint32(i))
		tmp := chain(sig[i*n:], lengths[i], w-1-lengths[i], adrs, pubSeed)
		copy(pubKey[i*n:], tmp)
	}

	return pubKey
}

// Verifies the given signature on the given message.
func Verify(pk, sig, msg, pubSeed []byte, adrs Address) bool {
	return bytes.Equal(pk, PkFromSig(sig, msg, pubSeed, adrs))
}
