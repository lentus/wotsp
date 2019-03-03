package wotsp

import (
	"crypto"
	"fmt"
	"runtime"
)

var (
	canPrecompute = map[crypto.Hash]bool{
		crypto.SHA256:      true,
		crypto.SHA512_256:  true,
		crypto.BLAKE2b_256: true,
		crypto.BLAKE2s_256: true,
	}
)

// Opts groups the parameters required for W-OTS+ operations. It implements
// crypto.SignerOpts.
type Opts struct {
	Mode    Mode
	Address Address

	// Concurrency specifies the amount of goroutines to use for WOTS
	// operations. Concurrency follows the following logic for n:
	//  n > 0: divide chains over n goroutines.
	//  n == 0: default, use a single goroutine
	//  n < 0: automatically determine the number of goroutines based on
	//         runtime.NumCPU or runtime.GOMAXPROX(-1), whichever is lower.
	Concurrency int

	// Hash specifies the specific hash function to use. For a hash function to
	// be accepted by the implementation, it needs to have a digest of 256 bits.
	//
	// Currently, the following values are supported:
	//	crypto.SHA256
	//	crypto.SHA512_256
	//	crypto.BLAKE2b_256
	//  crypto.BLAKE2s_256
	//
	// The default (for crypto.Hash(0)) is SHA256, as per the RFC.
	crypto.Hash

	// NOTE by embedding Hash we automatically implement crypto.SignerOpts, if
	// this were ever to become relevant.
}

// hash returns the hash function to use for the run of W-OTS+.
func (o Opts) hash() (crypto.Hash, error) {
	if o.Hash == crypto.Hash(0) {
		return crypto.SHA256, nil
	}

	if canPrecompute[o.Hash] {
		return o.Hash, nil
	}

	return 0, fmt.Errorf("unsupported value for Opts.Hash [%d]", o.Hash)
}

// routines returns the amount of simultaneous goroutines to use for W-OTS+
// operations, based on Opts.Concurrency.
func (o Opts) routines() int {
	if o.Concurrency == 0 {
		return 1
	}

	if o.Concurrency > 0 {
		return o.Concurrency
	}

	procs := runtime.GOMAXPROCS(-1)
	cpus := runtime.NumCPU()
	if procs > cpus {
		return cpus
	}
	return procs
}
