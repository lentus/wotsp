/*

Package wotsp implements WOTSP-SHA2_256 as documented in RFC 8391
(https://datatracker.ietf.org/doc/rfc8391/)

*/
package wotsp

import (
	"sync"
	"runtime"
	"crypto/subtle"
)

// N is a constant used by wotsp.
const N = 32

// Distributes the chains that must be computed between GOMAXPROCS goroutines.
//
// When fromSig is true, in contains a signature and out must be a public key;
// in this case the routines must complete the signature chains so they use
// lengths as start indices. If fromSig is false, we are either computing a
// public key from a private key, or a signature from a private key, so the
// routines use lengths as the amount of iterations to perform.
func computeChains(h *hasher, numRoutines int, in, out []byte, lengths []uint8, adrs *Address, p params, fromSig bool) {
	chainsPerRoutine := (p.l-1)/numRoutines + 1

	// Initialise scratch pad
	scratch := make([]byte, numRoutines*64)

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
			if lastChain >= p.l {
				lastChain = p.l - 1
			}

			// Compute the hash chains
			for j := firstChain; j <= lastChain; j++ {
				adrs.setChain(uint32(j))
				if fromSig {
					h.chain(nr, scratch, in[j*N:(j+1)*N], out[j*N:(j+1)*N], lengths[j], p.w-1-lengths[j], adrs)
				} else {
					h.chain(nr, scratch, in[j*N:(j+1)*N], out[j*N:(j+1)*N], 0, lengths[j], adrs)
				}
			}
			wg.Done()
		}(i, scratch[i*64:(i+1)*64], chainAdrs)
	}

	wg.Wait()
}

// Computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed, pubSeed []byte, opts Opts) (pubKey []byte, err error) {
	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	numRoutines := runtime.GOMAXPROCS(-1)
	h, err := newHasher(seed, pubSeed, opts, numRoutines)

	privKey := h.expandSeed()

	// Initialise list of chain lengths for full chains
	lengths := make([]uint8, params.l)
	for i := range lengths {
		lengths[i] = params.w - 1
	}

	adrs := opts.Address
	pubKey = make([]byte, params.l*N)
	computeChains(h, numRoutines, privKey, pubKey, lengths, &adrs, params, false)

	return
}

// Sign generates the signature of msg using the private key generated using the
// given seed.
func Sign(msg, seed, pubSeed []byte, opts Opts) (sig []byte, err error) {
	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	numRoutines := runtime.GOMAXPROCS(-1)
	h, err := newHasher(seed, pubSeed, opts, numRoutines)
	if err != nil {
		return
	}

	privKey := h.expandSeed()
	lengths := h.baseW(msg, params.l1)

	csum := h.checksum(lengths)
	lengths = append(lengths, csum...)

	adrs := opts.Address
	sig = make([]byte, params.l*N)
	computeChains(h, numRoutines, privKey, sig, lengths, &adrs, params, false)

	return
}

// Generates a public key from the given signature
func PublicKeyFromSig(sig, msg, pubSeed []byte, opts Opts) (pubKey []byte, err error) {
	numRoutines := runtime.GOMAXPROCS(-1)

	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	h, err := newHasher(nil, pubSeed, opts, numRoutines)
	if err != nil {
		return
	}

	lengths := h.baseW(msg, h.params.l1)

	csum := h.checksum(lengths)
	lengths = append(lengths, csum...)

	adrs := opts.Address
	pubKey = make([]byte, params.l*N)
	computeChains(h, numRoutines, sig, pubKey, lengths, &adrs, params, true)

	return
}

// Verify checks whether the signature is correct for the given message.
func Verify(pk, sig, msg, pubSeed []byte, opts Opts) (bool, error) {
	sig, err := PublicKeyFromSig(sig, msg, pubSeed, opts)
	if err != nil {
		return false, err
	}

	// use subtle.ConstantTimeCompare instead of bytes.Equal to avoid timing
	// attacks.
	return subtle.ConstantTimeCompare(pk, sig) == 1, nil
}
