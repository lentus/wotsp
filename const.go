package wotsp

// constants for WOTPS signatures for both W4 and W16 modes.
const (
	W4PublicKeyBytes = 4256        // size of public key
	W4SecretKeyBytes = W4SeedBytes // size of the secret key, which is the seed
	W4Bytes          = 4256        // size of signatures
	W4SeedBytes      = 32          // size of the secret seed
	W4PubSeedBytes   = 32          // size of the public seed
	W4AddressBytes   = 32          // size of the address value

	W16PublicKeyBytes = 2144
	W16SecretKeyBytes = W16SeedBytes
	W16Bytes          = 2144
	W16SeedBytes      = 32
	W16PubSeedBytes   = 32
	W16AddressBytes   = 32
)
