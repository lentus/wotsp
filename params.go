package wotsp

import (
	"crypto"
	"runtime"
)

// Opts groups the parameters required for WOTSP operations. It implements
// crypto.SignerOpts.
type Opts struct {
	Mode    Mode
	Address Address

	// Concurrency specifies the amount of goroutines to use for WOTS
	// operations. Concurrency follows the following logic for n:
	//	n > 0: divide chains over n goroutines.
	//  n == 0: default, use a single goroutine
	//  n < 0: automatically determine the number of goroutines based on
	//		   runtime.NumCPU or runtime.GOMAXPROX(-1), whichever is lower.
	Concurrency int
}

// Opts should implement crypto.SignerOpts
var _ crypto.SignerOpts = Opts{}

// WOTS uses SHA256 as its internal hash function, so HashFunc will always
// return crypto.SHA256.
func (Opts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// routines returns the amount of simultanious goroutines to use for WOTS
// operations, based on Opts.Concurrency.
func (o Opts) routines() int {
	if o.Concurrency == 0 {
		return 1
	}

	if o.Concurrency >= 0 {
		return o.Concurrency
	}

	procs := runtime.GOMAXPROCS(-1)
	cpus := runtime.NumCPU()
	if procs > cpus {
		return cpus
	}
	return procs
}

// params is an internal struct that defines required parameters in WOTS. The
// parameters are derived from a Mode.
type params struct {
	w         uint8
	logW      uint
	l1, l2, l int
}
