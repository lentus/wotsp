// Implements WOTSP-SHA2_256 as documented in RFC 8391
// (https://datatracker.ietf.org/doc/rfc8391/)
package wotsp

import (
	"encoding/binary"
	"bytes"
	"sync"
	"runtime"
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
		break
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
func chain(h *hasher, routineNr int, scratch, in, out []byte, start, steps uint8, adrs *Address) {
	copy(out, in)

	for i := start; i < start+steps && i < w; i++ {
		adrs.setHash(uint32(i))

		adrs.setKeyAndMask(0)
		h.prfPubSeed(routineNr, adrs, scratch[:32])
		adrs.setKeyAndMask(1)
		h.prfPubSeed(routineNr, adrs, scratch[32:64])

		for j := 0; j < n; j++ {
			out[j] = out[j] ^ scratch[32+j]
		}

		h.hashF(routineNr, scratch[:32], out)
	}
}

// Distributes the chains that must be computed between GOMAXPROCS goroutines.
//
// When fromSig is true, in contains a signature and out must be a public key;
// in this case the routines must complete the signature chains so they use
// lengths as start indices. If fromSig is false, we are either computing a
// public key from a private key, or a signature from a private key, so the
// routines use lengths as the amount of iterations to perform.
func computeChains(h *hasher, numRoutines int, in, out []byte, lengths []uint8, adrs *Address, fromSig bool) {
	chainsPerRoutine := (l-1)/numRoutines + 1

	// Initialise scratch pad
	scratch := make([]byte, numRoutines * 64)

	wg := new(sync.WaitGroup)
	for i := 0; i < numRoutines; i++ {
		// Copy address structure
		chainAdrs := new(Address)
		copy(chainAdrs.data[:], adrs.data[:])

		wg.Add(1)
		go func(nr int, scratch []byte, adrs *Address) {
			firstChain := nr * chainsPerRoutine
			lastChain := firstChain + chainsPerRoutine - 1

			// Make sure the last routine ends at the right chain
			if lastChain >= l {
				lastChain = l - 1
			}

			// Compute the hash chains
			for j := firstChain; j <= lastChain; j++ {
				adrs.setChain(uint32(j))
				if fromSig {
					chain(h, nr, scratch, in[j*n:(j+1)*n], out[j*n:(j+1)*n], lengths[j], w-1-lengths[j], adrs)
				} else {
					chain(h, nr, scratch, in[j*n:(j+1)*n], out[j*n:(j+1)*n], 0, lengths[j], adrs)
				}
			}
			wg.Done()
		}(i, scratch[i*64:(i+1)*64], chainAdrs)
	}

	wg.Wait()
}

// Expands a 32-byte seed into an (l*n)-byte private key.
func expandSeed(h *hasher) []byte {
	privKey := make([]byte, l*n)
	ctr := make([]byte, 32)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		h.prfPrivSeed(0, ctr, privKey[i*n:])
	}

	return privKey
}

// Computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed, pubSeed []byte, adrs *Address) []byte {
	numRoutines := runtime.GOMAXPROCS(-1)
	h := precompute(seed, pubSeed, numRoutines)

	privKey := expandSeed(h)

	// Initialise list of chain lengths for full chains
	lengths := make([]uint8, l)
	for i := range lengths {
		lengths[i] = w-1
	}

	pubKey := make([]byte, l*n)
	computeChains(h, numRoutines, privKey, pubKey, lengths, adrs, false)

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
	numRoutines := runtime.GOMAXPROCS(-1)
	h := precompute(seed, pubSeed, numRoutines)

	privKey := expandSeed(h)
	lengths := baseW(msg, l1)

	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	sig := make([]byte, l*n)
	computeChains(h, numRoutines, privKey, sig, lengths, adrs, false)

	return sig
}

// Generates a public key from the given signature
func PkFromSig(sig, msg, pubSeed []byte, adrs *Address) []byte {
	numRoutines := runtime.GOMAXPROCS(-1)
	h := precompute(nil, pubSeed, numRoutines)

	lengths := baseW(msg, l1)

	csum := checksum(lengths)
	lengths = append(lengths, csum...)

	pubKey := make([]byte, l*n)
	computeChains(h, numRoutines, sig, pubKey, lengths, adrs, true)

	return pubKey
}

// Verifies the given signature on the given message.
func Verify(pk, sig, msg, pubSeed []byte, adrs *Address) bool {
	return bytes.Equal(pk, PkFromSig(sig, msg, pubSeed, adrs))
}
