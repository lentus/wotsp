package wotsp

import (
	"testing"
	"bytes"
	"github.com/Re0h/wotsp/testdata"
	"crypto/rand"
)

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
	pubKey := GenPublicKey(testdata.Seed, testdata.PubSeed, &Address{})

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong key")
	}
}

func TestSign(t *testing.T) {
	signature := Sign(testdata.Message, testdata.Seed, testdata.PubSeed, &Address{})

	if !bytes.Equal(signature, testdata.Signature) {
		t.Error("Wrong signature")
	}
}

func TestPkFromSig(t *testing.T) {
	pubKey := PkFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, &Address{})

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong public key")
	}
}

func TestVerify(t *testing.T) {
	if !Verify(testdata.PubKey, testdata.Signature, testdata.Message, testdata.PubSeed, &Address{}) {
		t.Error("Wrong public key")
	}
}

func TestAll(t *testing.T) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		t.Fatal(err)
	}

	pubSeed := make([]byte, 32)
	_, err = rand.Read(pubSeed)
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	if err != nil {
		t.Fatal(err)
	}

	pubKey := GenPublicKey(seed, pubSeed, &Address{})
	signed := Sign(msg, seed, pubSeed, &Address{})

	if !Verify(pubKey, signed, msg, pubSeed, &Address{}) {
		t.Fail()
	}
}

func TestW4(t *testing.T) {
	SetMode(W4)

	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		t.Fatal(err)
	}

	pubSeed := make([]byte, 32)
	_, err = rand.Read(pubSeed)
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	if err != nil {
		t.Fatal(err)
	}

	pubKey := GenPublicKey(seed, pubSeed, &Address{})
	signed := Sign(msg, seed, pubSeed, &Address{})

	if !Verify(pubKey, signed, msg, pubSeed, &Address{}) {
		t.Fail()
	}
}

func BenchmarkGenPublicKey(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = GenPublicKey(testdata.Seed, testdata.PubSeed, &Address{})
	}
}

func BenchmarkSign(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Sign(testdata.Message, testdata.Seed, testdata.PubSeed, &Address{})
	}
}

func BenchmarkPkFromSig(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = PkFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, &Address{})
	}
}

func BenchmarkW4GenPublicKey(b *testing.B) {
	b.ReportAllocs()
	SetMode(W4)
	for i := 0; i < b.N; i++ {
		_ = GenPublicKey(testdata.Seed, testdata.PubSeed, &Address{})
	}
}

func BenchmarkW4Sign(b *testing.B) {
	b.ReportAllocs()
	SetMode(W4)
	for i := 0; i < b.N; i++ {
		_ = Sign(testdata.Message, testdata.Seed, testdata.PubSeed, &Address{})
	}
}

func BenchmarkW4PkFromSig(b *testing.B) {
	b.ReportAllocs()
	SetMode(W4)
	for i := 0; i < b.N; i++ {
		_ = PkFromSig(testdata.SignatureW4, testdata.Message, testdata.PubSeed, &Address{})
	}
}
