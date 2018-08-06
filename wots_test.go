package wotsp

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/lentus/wotsp/testdata"
)

// noerr is a helper that triggers t.Fatal[f] if the error is non-nil.
func noerr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("error occured: [%s]", err.Error())
	}
}

func TestAddressToBytes(t *testing.T) {
	a := Address{}
	a.SetLayer(0x10111119)
	a.SetTree(0x2022222930333339)
	a.SetType(0x40444449)
	a.SetOTS(0x50555559)
	a.setChain(0x60666669)
	a.setHash(0x70777779)
	a.setKeyAndMask(0x80888889)

	aBytes := []byte{
		0x10, 0x11, 0x11, 0x19,
		0x20, 0x22, 0x22, 0x29,
		0x30, 0x33, 0x33, 0x39,
		0x40, 0x44, 0x44, 0x49,
		0x50, 0x55, 0x55, 0x59,
		0x60, 0x66, 0x66, 0x69,
		0x70, 0x77, 0x77, 0x79,
		0x80, 0x88, 0x88, 0x89,
	}

	if !bytes.Equal(a.ToBytes(), aBytes) {
		t.Error("Got ", a.ToBytes(), " wanted ", aBytes)
	}
}

func TestGenPublicKey(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	pubKey, err := GenPublicKey(testdata.Seed, testdata.PubSeed, opts)
	noerr(t, err)

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong key")
	}
}

func TestSign(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	signature, err := Sign(testdata.Message, testdata.Seed, testdata.PubSeed, opts)
	noerr(t, err)

	if !bytes.Equal(signature, testdata.Signature) {
		t.Error("Wrong signature")
	}
}

func TestPkFromSig(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	pubKey, err := PublicKeyFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, opts)
	noerr(t, err)

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong public key")
	}
}

func TestVerify(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	ok, err := Verify(testdata.PubKey, testdata.Signature, testdata.Message, testdata.PubSeed, opts)
	noerr(t, err)

	if !ok {
		t.Error("Wrong public key")
	}
}

func TestAll(t *testing.T) {
	var opts Opts
	opts.Mode = W16 // explicit, in case the default ever changes

	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	noerr(t, err)

	pubSeed := make([]byte, 32)
	_, err = rand.Read(pubSeed)
	noerr(t, err)

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	noerr(t, err)

	pubKey, err := GenPublicKey(seed, pubSeed, opts)
	noerr(t, err)

	signed, err := Sign(msg, seed, pubSeed, opts)
	noerr(t, err)

	valid, err := Verify(pubKey, signed, msg, pubSeed, opts)
	noerr(t, err)
	if !valid {
		t.Fail()
	}
}

func TestW4(t *testing.T) {

	var opts Opts
	opts.Mode = W4

	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	noerr(t, err)

	pubSeed := make([]byte, 32)
	_, err = rand.Read(pubSeed)
	noerr(t, err)

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	noerr(t, err)

	pubKey, err := GenPublicKey(seed, pubSeed, opts)
	noerr(t, err)

	signed, err := Sign(msg, seed, pubSeed, opts)
	noerr(t, err)

	valid, err := Verify(pubKey, signed, msg, pubSeed, opts)
	noerr(t, err)
	if !valid {
		t.Fail()
	}
}

func BenchmarkGenPublicKey(b *testing.B) {
	b.ReportAllocs()

	opts := Opts{
		Mode:    W16,
	}

	for i := 0; i < b.N; i++ {
		GenPublicKey(testdata.Seed, testdata.PubSeed, opts)
	}
}

func BenchmarkSign(b *testing.B) {
	b.ReportAllocs()

	opts := Opts{
		Mode:    W16,
	}

	for i := 0; i < b.N; i++ {
		Sign(testdata.Message, testdata.Seed, testdata.PubSeed, opts)
	}
}

func BenchmarkPkFromSig(b *testing.B) {
	b.ReportAllocs()

	opts := Opts{
		Mode:    W16,
	}

	for i := 0; i < b.N; i++ {
		PublicKeyFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, opts)
	}
}

func BenchmarkW4GenPublicKey(b *testing.B) {
	b.ReportAllocs()

	opts := Opts{
		Mode:    W4,
	}

	for i := 0; i < b.N; i++ {
		GenPublicKey(testdata.Seed, testdata.PubSeed, opts)
	}
}

func BenchmarkW4Sign(b *testing.B) {
	b.ReportAllocs()

	opts := Opts{
		Mode:    W4,
	}

	for i := 0; i < b.N; i++ {
		Sign(testdata.Message, testdata.Seed, testdata.PubSeed, opts)
	}
}

func BenchmarkW4PkFromSig(b *testing.B) {
	b.ReportAllocs()

	opts := Opts{
		Mode:    W16,
	}

	for i := 0; i < b.N; i++ {
		PublicKeyFromSig(testdata.SignatureW4, testdata.Message, testdata.PubSeed, opts)
	}
}
