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

	// Hash function instances
	hasher []hash.Hash
	// Hash digests of hasher
	hasherVal []reflect.Value

	// PRF with precomputed hash digests for pub and priv seeds
	prfPubSeed  func(routineNr int, addr *Address, out []byte)
	prfPrivSeed func(routineNr int, ctr []byte, out []byte)
	hashF       func(routineNr int, key, inout []byte)
}

func precompute(privSeed, pubSeed []byte, nrRoutines int) *hasher {
	c := new(hasher)
	c.hasher = make([]hash.Hash, nrRoutines)
	c.hasherVal = make([]reflect.Value, nrRoutines)

	for i := 0; i < nrRoutines; i++ {
		c.hasher[i] = sha256.New()
		c.hasherVal[i] = reflect.ValueOf(c.hasher[i]).Elem()
	}

	padding := make([]byte, n)

	// While padding is all zero, precompute hashF
	hashHashF := sha256.New()
	hashHashF.Write(padding)

	c.precompHashF = reflect.ValueOf(hashHashF).Elem()

	c.hashF = func(routineNr int, key, inout []byte) {
		c.hasherVal[routineNr].Set(c.precompHashF)
		c.hasher[routineNr].Write(key)
		c.hasher[routineNr].Write(inout)
		c.hasher[routineNr].Sum(inout[:0])
	}

	// Set padding for prf
	binary.BigEndian.PutUint16(padding[n-2:], uint16(3))

	if privSeed != nil {
		// Precompute prf with private seed (not used in PkFromSig)
		hashPrfSk := sha256.New()
		hashPrfSk.Write(padding)
		hashPrfSk.Write(privSeed)

		c.precompPrfPrivSeed = reflect.ValueOf(hashPrfSk).Elem()

		c.prfPrivSeed = func(routineNr int, ctr []byte, out []byte) {
			c.hasherVal[routineNr].Set(c.precompPrfPrivSeed)
			c.hasher[routineNr].Write(ctr)
			c.hasher[routineNr].Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
		}
	}

	// Precompute prf with public seed
	hashPrfPub := sha256.New()
	hashPrfPub.Write(padding)
	hashPrfPub.Write(pubSeed)

	c.precompPrfPubSeed = reflect.ValueOf(hashPrfPub).Elem()

	c.prfPubSeed = func(routineNr int, addr *Address, out []byte) {
		c.hasherVal[routineNr].Set(c.precompPrfPubSeed)
		c.hasher[routineNr].Write(addr.ToBytes())
		c.hasher[routineNr].Sum(out[:0]) // Must make sure that out's capacity is >= 32 bytes!
	}

	return c
}

