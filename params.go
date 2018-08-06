package wotsp

import (
	"crypto"
)

// Opts groups the parameters required for WOTSP operations. It implements
// crypto.SignerOpts.
type Opts struct {
	Mode    Mode
	Address Address
}

// Opts should implement crypto.SignerOpts
var _ crypto.SignerOpts = Opts{}

// WOTS uses SHA256 as its internal hash function, so HashFunc will always
// return crypto.SHA256.
func (Opts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// params is an internal struct that defines required parameters in WOTS. The
// parameters are derived from a Mode.
type params struct {
	w         uint8
	logW      uint
	l1, l2, l int
}
