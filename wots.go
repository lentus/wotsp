/*

Package wotsp implements WOTSP-SHA2_256 as documented in RFC 8391
(https://datatracker.ietf.org/doc/rfc8391/)

*/
package wotsp

import (
	"crypto/subtle"
)

// N is a constant used by wotsp.
const N = 32

// GenPublicKey computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed []byte, opts Opts) (pk []byte, err error) {
	h := precompute(seed, opts.PubSeed)

	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	privKey := params.expandSeed(h)
	scratch := make([]byte, 64)

	pk = make([]byte, params.l*N)
	addr := opts.Address
	for i := 0; i < params.l; i++ {
		addr.setChain(uint32(i))
		params.chain(h, scratch, privKey[i*N:], pk[i*N:(i+1)*N], 0, params.w-1, &addr)
	}

	return
}

// Sign generates the signature of msg using the private key generated using the
// given seed.
func Sign(msg, seed []byte, opts Opts) (sig []byte, err error) {
	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	h := precompute(seed, opts.PubSeed)

	privKey := params.expandSeed(h)
	lengths := params.baseW(msg, params.l1)
	scratch := make([]byte, 64)

	csum := params.checksum(lengths)
	lengths = append(lengths, csum...)

	sig = make([]byte, params.l*N)
	addr := opts.Address
	for i := 0; i < params.l; i++ {
		addr.setChain(uint32(i))
		params.chain(h, scratch, privKey[i*N:], sig[i*N:(i+1)*N], 0, lengths[i], &addr)
	}

	return
}

// PublicKeyFromSig generates a public key from the given signature.
func PublicKeyFromSig(sig, msg []byte, opts Opts) (pk []byte, err error) {
	params, err := opts.Mode.params()
	if err != nil {
		return
	}

	h := precompute(nil, opts.PubSeed)

	lengths := params.baseW(msg, params.l1)
	scratch := make([]byte, 64)

	csum := params.checksum(lengths)
	lengths = append(lengths, csum...)

	pk = make([]byte, params.l*N)
	addr := opts.Address
	for i := 0; i < params.l; i++ {
		addr.setChain(uint32(i))
		params.chain(h, scratch, sig[i*N:], pk[i*N:(i+1)*N], lengths[i], params.w-1-lengths[i], &addr)
	}

	return
}

// Verify checks whether the signature is correct for the given message.
func Verify(pk, sig, msg []byte, opts Opts) (bool, error) {
	sig, err := PublicKeyFromSig(sig, msg, opts)
	if err != nil {
		return false, err
	}

	// use subtle.ConstantTimeCompare instead of bytes.Equal to avoid timing
	// attacks.
	return subtle.ConstantTimeCompare(pk, sig) == 1, nil
}
