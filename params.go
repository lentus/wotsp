package wotsp

import (
	"crypto"
)

// Opts groups the parameters required for WOTSP operations.
//
// Opts implements crypto.SignerOpts and crypto.DecrypterOpts.
type Opts struct {
	Mode    Mode
	PubSeed []byte
	Address Address
}

// mode should implement crypto.SignerOpts
var _ crypto.SignerOpts = Opts{}

// HashFunc implements crypto.SignerOpts.
//
// WOTS uses SHA256 as its internal hash function, so HashFunc will always
// return crypto.SHA256.
func (Opts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// params is an internal struct that defines parameters that specify a "Mode" in
// WOTS.
type params struct {
	w         uint8
	logW      uint
	l1, l2, l int
}
