package wotsp

import (
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

	// Hash function instances
	hashers []hash.Hash
	// Hash digests of hashers
	hasherVals []reflect.Value
}

func newHasher(privSeed, pubSeed []byte, opts Opts, nrRoutines int) *hasher {
	hashFunc := opts.hash()

	h := new(hasher)
	h.params = opts.Mode.params()
	h.hashers = make([]hash.Hash, nrRoutines)
	h.hasherVals = make([]reflect.Value, nrRoutines)

	for i := 0; i < nrRoutines; i++ {
		h.hashers[i] = hashFunc.New()
		h.hasherVals[i] = reflect.ValueOf(h.hashers[i]).Elem()
	}

	padding := make([]byte, N)

	// While padding is all zero, precompute hashF
	precompHashF := hashFunc.New()
	precompHashF.Write(padding)
	h.precompHashF = reflect.ValueOf(precompHashF).Elem()

	// Set padding for prf
	binary.BigEndian.PutUint16(padding[N-2:], uint16(3))

	if privSeed != nil {
		// Precompute prf with private seed (not used in PkFromSig)
		precompPrfPrivSeed := hashFunc.New()
		precompPrfPrivSeed.Write(padding)
		precompPrfPrivSeed.Write(privSeed)
		h.precompPrfPrivSeed = reflect.ValueOf(precompPrfPrivSeed).Elem()
	}

	// Precompute prf with public seed
	precompPrfPubSeed := hashFunc.New()
	precompPrfPubSeed.Write(padding)
	precompPrfPubSeed.Write(pubSeed)
	h.precompPrfPubSeed = reflect.ValueOf(precompPrfPubSeed).Elem()

	return h
}

//
// PRF with precomputed hash digests for pub and priv seeds
//

func (h *hasher) hashF(routineNr int, key, inout []byte) {
	h.hasherVals[routineNr].Set(h.precompHashF)
	h.hashers[routineNr].Write(key)
	h.hashers[routineNr].Write(inout)
	h.hashers[routineNr].Sum(inout[:0])
}

func (h *hasher) prfPubSeed(routineNr int, addr *[32]byte, out []byte) {
	h.hasherVals[routineNr].Set(h.precompPrfPubSeed)
	h.hashers[routineNr].Write(addr[:])
	h.hashers[routineNr].Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
}

func (h *hasher) prfPrivSeed(routineNr int, ctr []byte, out []byte) {
	h.hasherVals[routineNr].Set(h.precompPrfPrivSeed)
	h.hashers[routineNr].Write(ctr)
	h.hashers[routineNr].Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
}

// Computes the base-w representation of a binary input.
func (h *hasher) baseW(x []byte, outLen int) []uint8 {
	var total byte
	in := 0
	out := 0
	bits := uint(0)
	baseW := make([]uint8, outLen)

	logW := h.params.logW
	w := h.params.w

	for consumed := 0; consumed < outLen; consumed++ {
		if bits == 0 {
			total = x[in]
			in++
			bits += 8
		}

		bits -= logW
		baseW[out] = (total >> bits) & byte(w-1)
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
func (h *hasher) chain(routineNr int, scratch, in, out []byte, start, steps uint8, adrs *[32]byte) {
	copy(out, in)

	for i := start; i < start+steps; i++ {
		setHash(adrs, uint32(i))

		setKeyAndMask(adrs, 0)
		h.prfPubSeed(routineNr, adrs, scratch[:32])
		setKeyAndMask(adrs, 1)
		h.prfPubSeed(routineNr, adrs, scratch[32:64])

		for j := 0; j < N; j++ {
			out[j] = out[j] ^ scratch[32+j]
		}

		h.hashF(routineNr, scratch[:32], out)
	}
}

func setHash(address *[32]byte, hash uint32) {
	binary.BigEndian.PutUint32(address[24:], hash)
}

func setKeyAndMask(address *[32]byte, keyAndMask uint32) {
	binary.BigEndian.PutUint32(address[28:], keyAndMask)
}

// Expands a 32-byte seed into an (l*n)-byte private key.
func (h *hasher) expandSeed() []byte {
	l := h.params.l

	privKey := make([]byte, l*N)
	ctr := make([]byte, 32)

	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint16(ctr[30:], uint16(i))
		h.prfPrivSeed(0, ctr, privKey[i*N:])
	}

	return privKey
}

func (h *hasher) checksum(msg []uint8) []uint8 {
	l1, l2, w, logW := h.params.l1, h.params.l2, h.params.w, h.params.logW

	csum := uint32(0)
	for i := 0; i < l1; i++ {
		csum += uint32(uint8(w-1) - msg[i])
	}
	csum <<= 8 - ((uint(l2) * logW) % 8)

	// Length of the checksum is (l2*logw + 7) / 8
	csumBytes := make([]byte, 2)
	// Since bytesLen is always 2, we can truncate csum to a uint16.
	binary.BigEndian.PutUint16(csumBytes, uint16(csum))

	return h.baseW(csumBytes, l2)
}

// Distributes the chains that must be computed between numRoutine goroutines.
//
// When fromSig is true, 'in' contains a signature and 'out' must be a public
// key; in this case the routines must complete the signature chains so they
// use lengths as start indices. If fromSig is false, we are either computing a
// public key from a private key, or a signature from a private key, so the
// routines use lengths as the amount of iterations to perform.
func (h *hasher) computeChains(numRoutines int, in, out []byte, lengths []uint8, adrs *[32]byte, p params, fromSig bool) {
	chainsPerRoutine := (p.l-1)/numRoutines + 1

	// Initialise scratch pad
	scratch := make([]byte, numRoutines*64)

	done := make(chan struct{}, numRoutines)

	computeChain := func(nr int, scratch []byte, adrs [32]byte) {
		firstChain := nr * chainsPerRoutine
		lastChain := firstChain + chainsPerRoutine - 1

		// Make sure the last routine ends at the right chain
		if lastChain >= p.l {
			lastChain = p.l - 1
		}

		// Compute the hash chains
		for chainIdx := firstChain; chainIdx <= lastChain; chainIdx++ {
			setChain(&adrs, uint32(chainIdx))

			input := in[chainIdx*N : (chainIdx+1)*N]
			output := out[chainIdx*N : (chainIdx+1)*N]

			var start, end uint8
			if fromSig {
				start = lengths[chainIdx]
				end = uint8(p.w-1) - lengths[chainIdx]
			} else {
				start = 0
				end = lengths[chainIdx]
			}

			h.chain(nr, scratch, input, output, start, end, &adrs)
		}

		done <- struct{}{}
	}

	// Start chain computations
	for routineIdx := 0; routineIdx < numRoutines; routineIdx++ {
		// adrs is passed by value here to create a new reference
		go computeChain(routineIdx, scratch[routineIdx*64:(routineIdx+1)*64], *adrs)
	}

	// Wait for chain computations to complete
	for i := 0; i < numRoutines; i++ {
		<-done
	}
}

func setChain(address *[32]byte, chain uint32) {
	binary.BigEndian.PutUint32(address[20:], chain)
}
