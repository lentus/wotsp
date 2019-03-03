/*

Package wotsp implements WOTSP-SHA2_256 as documented in RFC 8391
(https://datatracker.ietf.org/doc/rfc8391/).

W-OTS+ is a one-time hash-based signature scheme that is most commonly used in
a larger scheme such as XMSS or SPHINCS. As a W-OTS+ private key/private seed
can only be used once securely, W-OTS+ should not be used directly to create
signatures in most situations. This package is thus meant primarily to be used
in larger structures such as SPHINCS.

Since SHA512_256, BLAKE2b_256 and BLAKE2s_256 work out of the box, they can be
used as the internal hash function as well by setting Opts.Hash to their
corresponding crypto.Hash values.

*/
package wotsp

import (
	"crypto/subtle"
)

// N is a constant defined as the output length of the used hash function.
const N = 32

// GenPublicKey computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed, pubSeed []byte, opts Opts) (pubKey []byte, err error) {
	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	numRoutines := opts.routines()
	h, err := newHasher(seed, pubSeed, opts, numRoutines)

	privKey := h.expandSeed()

	// Initialise list of chain lengths for full chains
	lengths := make([]uint8, params.l)
	for i := range lengths {
		lengths[i] = uint8(params.w - 1)
	}

	adrs := opts.Address
	pubKey = make([]byte, params.l*N)
	h.computeChains(numRoutines, privKey, pubKey, lengths, &adrs, params, false)

	return
}

// Sign generates the signature of msg using the private key generated using the
// given seed.
func Sign(msg, seed, pubSeed []byte, opts Opts) (sig []byte, err error) {
	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	numRoutines := opts.routines()
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
	h.computeChains(numRoutines, privKey, sig, lengths, &adrs, params, false)

	return
}

// PublicKeyFromSig generates a public key from the given signature
func PublicKeyFromSig(sig, msg, pubSeed []byte, opts Opts) (pubKey []byte, err error) {
	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	numRoutines := opts.routines()
	h, err := newHasher(nil, pubSeed, opts, numRoutines)
	if err != nil {
		return
	}

	lengths := h.baseW(msg, h.params.l1)

	csum := h.checksum(lengths)
	lengths = append(lengths, csum...)

	adrs := opts.Address
	pubKey = make([]byte, params.l*N)
	h.computeChains(numRoutines, sig, pubKey, lengths, &adrs, params, true)

	return
}

// Verify checks whether the signature is correct for the given message.
func Verify(pk, sig, msg, pubSeed []byte, opts Opts) (valid bool, err error) {
	if sig, err = PublicKeyFromSig(sig, msg, pubSeed, opts); err != nil {
		return
	}

	// use subtle.ConstantTimeCompare instead of bytes.Equal to avoid timing
	// attacks.
	valid = subtle.ConstantTimeCompare(pk, sig) == 1
	return
}
