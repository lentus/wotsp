package wotsp

// constants for WOTPS signatures for both W4 and W16 modes.
const (
	W4PublicKeyBytes = 2144        // size of publis key
	W4SecretKeyBytes = W4SeedBytes // TODO should this be the size of the internal private key, or the seed?
	W4Bytes          = 2144        // size of signatures
	W4SeedBytes      = 32
	W4PubSeedBytes   = 32

	W16PublicKeyBytes = 2144
	W16SecretKeyBytes = W16SeedBytes
	W16Bytes          = 4256
	W16SeedBytes      = 32
	W16PubSeedBytes   = 32
)
