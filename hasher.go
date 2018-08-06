package wotsp

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"reflect"
)

// The hasher struct implements the W-OTS+ functions PRF and HashF efficiently
// by precomputing part of the hash digests. Using precomputation improves
// performance by ~41%.
//
// Since the PRF function calculates H(toByte(3, 32) || seed || M), where seed
// can be the secret or public seed, the first 64 bytes of the input are
// recomputed on every evaluation of PRF. We can significantly improve
// performance by precomputing the hash digest for this part of the input.
//
// For HashF we can only precompute the first 32 bytes of hash digest: it
// calculates H(toByte(0, 32) || key || M) where key is the result of an
// evaluation of PRF.
type hasher struct {
	// Precomputed hash digests
	precompPrfPubSeed  reflect.Value
	precompPrfPrivSeed reflect.Value
	precompHashF       reflect.Value

	// params based on the mode
	params params

	// Hash function instance
	hasher hash.Hash
	// Hash digest of hasher
	hasherVal reflect.Value
}

// newHasher creates a new hasher instance for computations, and performs some
// precomputations to improve performance.
func newHasher(privSeed []byte, opts Opts) (h *hasher, err error) {
	h = new(hasher)

	if h.params, err = opts.Mode.params(); err != nil {
		return
	}

	h.hasher = sha256.New()
	h.hasherVal = reflect.ValueOf(h.hasher).Elem()

	padding := make([]byte, N)

	// While padding is all zero, precompute hashF
	hashHashF := sha256.New()
	hashHashF.Write(padding)

	h.precompHashF = reflect.ValueOf(hashHashF).Elem()

	// Set padding for prf
	binary.BigEndian.PutUint16(padding[N-2:], uint16(3))

	if privSeed != nil {
		// Precompute prf with private seed (not used in PkFromSig)
		hashPrfSk := sha256.New()
		hashPrfSk.Write(padding)
		hashPrfSk.Write(privSeed)

		h.precompPrfPrivSeed = reflect.ValueOf(hashPrfSk).Elem()
	}

	// Precompute prf with public seed
	hashPrfPub := sha256.New()
	hashPrfPub.Write(padding)
	hashPrfPub.Write(opts.PubSeed)

	h.precompPrfPubSeed = reflect.ValueOf(hashPrfPub).Elem()

	return
}

//
// PRF with precomputed hash digests for pub and priv seeds
//

func (h *hasher) hashF(key, inout []byte) {
	h.hasherVal.Set(h.precompHashF)
	h.hasher.Write(key)
	h.hasher.Write(inout)
	h.hasher.Sum(inout[:0])
}

func (h *hasher) prfPubSeed(addr *Address, out []byte) {
	h.hasherVal.Set(h.precompPrfPubSeed)
	h.hasher.Write(addr.data[:])
	h.hasher.Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
}

func (h *hasher) prfPrivSeed(ctr []byte, out []byte) {
	h.hasherVal.Set(h.precompPrfPrivSeed)
	h.hasher.Write(ctr)
	h.hasher.Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
}

// Computes the base-16 representation of a binary input.
func (h *hasher) baseW(x []byte, outlen int) []uint8 {
	var total byte
	in := 0
	out := 0
	bits := uint(0)
	baseW := make([]uint8, outlen)

	logW := h.params.logW
	w := h.params.w

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
func (h *hasher) chain(scratch, in, out []byte, start, steps uint8, adrs *Address) {
	copy(out, in)

	w := h.params.w

	for i := start; i < start+steps && i < w; i++ {
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
func (h *hasher) expandSeed() []byte {
	l := h.params.l

	privKey := make([]byte, l*N)
	ctr := make([]byte, 32)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		h.prfPrivSeed(ctr, privKey[i*N:])
	}

	return privKey
}

func (h *hasher) checksum(msg []uint8) []uint8 {
	l1, l2, w, logW := h.params.l1, h.params.l2, h.params.w, h.params.logW

	csum := uint32(0)
	for i := 0; i < l1; i++ {
		csum += uint32(w - 1 - msg[i])
	}
	csum <<= 8 - ((uint(l2) * logW) % 8)

	// Length of the checksum is (l2*logw + 7) / 8
	csumBytes := make([]byte, 2)
	// Since bytesLen is always 2, we can truncate csum to a uint16.
	binary.BigEndian.PutUint16(csumBytes, uint16(csum))

	return h.baseW(csumBytes, l2)
}
