// Implements WOTSP-SHA2_256 as documented in the IETF XMSS draft
// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)
package wotsp

type Address struct {
	Layer      uint32
	Tree       uint64
	Type       uint32
	OTS        uint32
	Chain      uint32
	Hash       uint32
	KeyAndMask uint32
}

const PADDING_F = 0
const PADDING_PRF = 3

const n = 32
const w = 16
const l = 67

// Computes the base-w representation of a binary input.
func baseW(in []byte) (out []int) {
	return nil
}

// Generates pseudo random outputs using a key and index.
// Message is padded as (toByte(3, 32) || KEY || M)
func prf(key, index []byte) (out []byte) {
	return nil
}

// Keyed hash function. Message is padded as follows:
//	(toByte(0, 32) || KEY || M)
func hash(in, key []byte) (out []byte) {
	return nil
}

// Expands a seed into a private key sk and randomization elements r.
func expandSeed(seed uint32) (sk, r []uint32) {
	return nil, nil
}

// Performs the chaining operation. Assumes the input is the <start>-th element
// in the chain, and performs <steps> iterations.
func chain(in []byte, start, steps uint) (out []byte) {
	return nil
}

// Computes the public key that corresponds to the expanded seed.
func GenPublicKey(seed uint32) {

}

// Signs message msg using the private key generated using the given seed.
func Sign(seed uint32, msg []byte) {

}

// Verifies the given signature on the given message.
func Verify(sig, msg []byte) {

}
