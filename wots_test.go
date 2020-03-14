package wotsp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/lentus/wotsp/testdata"

	// ensure our crypto is available. This is part of the tests, but not of the
	// library itself, to avoid including more packages than the library's user
	// will actually need.
	_ "crypto/sha256"
)

// noerr is a helper that triggers t.Fatal[f] if the error is non-nil.
func noerr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("error occurred: [%s]", err.Error())
	}
}

// TestGenPublicKey verifies the public key generation algorithm by comparing
// the resulting public key to a public key obtained from the reference
// implementation of RFC 8391.
func TestGenPublicKey(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	pubKey := GenPublicKey(testdata.Seed, testdata.PubSeed, opts)

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong key")
	}
}

// TestSign verifies the signing algorithm by comparing the resulting signature
// to a signature obtained from the reference implementation of RFC 8391.
func TestSign(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	signature := Sign(testdata.Message, testdata.Seed, testdata.PubSeed, opts)

	if !bytes.Equal(signature, testdata.Signature) {
		t.Error("Wrong signature")
	}
}

// TestPkFromSig verifies the public key from signature algorithm by comparing
// the resulting public key to a public key obtained from the reference
// implementation of RFC 8391.
func TestPkFromSig(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	pubKey := PublicKeyFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, opts)

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong public key")
	}
}

func TestVerify(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	ok := Verify(testdata.PubKey, testdata.Signature, testdata.Message, testdata.PubSeed, opts)

	if !ok {
		t.Error("Wrong public key")
	}
}

// TestAll verifies the three signature scheme algorithms for all parameter
// sets by generating a public key and a signature, and verifying the signature
// for that public key.
func TestAll(t *testing.T) {
	for _, mode := range []Mode{W4, W16, W256} {
		var opts Opts
		opts.Mode = mode

		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		noerr(t, err)

		pubSeed := make([]byte, 32)
		_, err = rand.Read(pubSeed)
		noerr(t, err)

		msg := make([]byte, 32)
		_, err = rand.Read(msg)
		noerr(t, err)

		t.Run(fmt.Sprintf("TestAll-%s", opts.Mode),
			func(t *testing.T) {
				pubKey := GenPublicKey(seed, pubSeed, opts)

				signed := Sign(msg, seed, pubSeed, opts)

				valid := Verify(pubKey, signed, msg, pubSeed, opts)
				if !valid {
					t.Fail()
				}
			})
	}
}

func BenchmarkWOTSP(b *testing.B) {
	for _, mode := range []Mode{W4, W16, W256} {
		runBenches(b, mode)
	}
}

// runBenches runs the set of main benchmarks
func runBenches(b *testing.B, mode Mode) {
	// test setup
	var signature []byte
	switch mode {
	case W4:
		signature = testdata.SignatureW4
	case W256:
		signature = testdata.SignatureW256
	default:
		signature = testdata.Signature
	}

	// create opts
	var opts Opts
	opts.Mode = mode
	opts.Concurrency = -1

	var maxRoutines = opts.routines()

	// for each level of concurrency, run the benchmarks on this set of options.
	for i := 1; i <= maxRoutines; i++ {
		opts.Concurrency = i

		b.Run(fmt.Sprintf("GenPublicKey-%s-%d", opts.Mode, i),
			func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = GenPublicKey(testdata.Seed, testdata.PubSeed, opts)
				}
			})
	}

	for i := 1; i <= maxRoutines; i++ {
		opts.Concurrency = i

		b.Run(fmt.Sprintf("Sign-%s-%d", opts.Mode, i),
			func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = Sign(testdata.Message, testdata.Seed, testdata.PubSeed, opts)
				}
			})
	}

	for i := 1; i <= maxRoutines; i++ {
		opts.Concurrency = i

		b.Run(fmt.Sprintf("PublicKeyFromSig-%s-%d", opts.Mode, i),
			func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = PublicKeyFromSig(signature, testdata.Message, testdata.PubSeed, opts)
				}
			})
	}
}
