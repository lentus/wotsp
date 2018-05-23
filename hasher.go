package wotsp

import (
	"reflect"
	"hash"
	"crypto/sha256"
	"encoding/binary"
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

	// Hash function instance
	hasher hash.Hash
	// Hash digest of hasher
	hasherVal reflect.Value

	// PRF with precomputed hash digests for pub and priv seeds
	prfPubSeed  func(addr *Address, out []byte)
	prfPrivSeed func(ctr []byte, out []byte)
	hashF       func(key, inout []byte)
}

func precompute(privSeed, pubSeed []byte) *hasher {
	c := new(hasher)
	c.hasher = sha256.New()
	c.hasherVal = reflect.ValueOf(c.hasher).Elem()

	padding := make([]byte, n)

	// While padding is all zero, precompute hashF
	hashHashF := sha256.New()
	hashHashF.Write(padding)

	c.precompHashF = reflect.ValueOf(hashHashF).Elem()

	c.hashF = func(key, inout []byte) {
		c.hasherVal.Set(c.precompHashF)
		c.hasher.Write(key)
		c.hasher.Write(inout)
		c.hasher.Sum(inout[:0])
	}

	// Set padding for prf
	binary.BigEndian.PutUint16(padding[n-2:], uint16(3))

	if privSeed != nil {
		// Precompute prf with private seed (not used in PkFromSig)
		hashPrfSk := sha256.New()
		hashPrfSk.Write(padding)
		hashPrfSk.Write(privSeed)

		c.precompPrfPrivSeed = reflect.ValueOf(hashPrfSk).Elem()

		c.prfPrivSeed = func(ctr []byte, out []byte) {
			c.hasherVal.Set(c.precompPrfPrivSeed)
			c.hasher.Write(ctr)
			c.hasher.Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
		}
	}

	// Precompute prf with public seed
	hashPrfPub := sha256.New()
	hashPrfPub.Write(padding)
	hashPrfPub.Write(pubSeed)

	c.precompPrfPubSeed = reflect.ValueOf(hashPrfPub).Elem()

	c.prfPubSeed = func(addr *Address, out []byte) {
		c.hasherVal.Set(c.precompPrfPubSeed)
		c.hasher.Write(addr.ToBytes())
		c.hasher.Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
	}

	return c
}

