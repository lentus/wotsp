package wotsp

import (
	"testing"
	"bytes"
	"github.com/Re0h/wotsp/testdata"
)

func TestBase16(t *testing.T) {
	input := []byte{0x12, 0x34}
	want := []uint8{1, 2, 3, 4}

	output := base16(input, 4)
	if !bytes.Equal(output, want) {
		t.Error("base16(", input, "): got ", output, " wanted ", want)
	}

	output = base16(input, 3)
	if !bytes.Equal(output, want[:3]) {
		t.Error("base16(", input, "): got ", output, " wanted ", want)
	}

	output = base16(input, 2)
	if !bytes.Equal(output, want[:2]) {
		t.Error("base16(", input, "): got ", output, " wanted ", want)
	}

	output = base16(input, 1)
	if !bytes.Equal(output, want[:1]) {
		t.Error("base16(", input, "): got ", output, " wanted ", want)
	}

}

func TestAddressToBytes(t *testing.T) {
	a := &Address{
		Layer:      0x10111119,
		Tree:       0x2022222930333339,
		Type:       0x40444449,
		OTS:        0x50555559,
		Chain:      0x60666669,
		Hash:       0x70777779,
		KeyAndMask: 0x80888889,
	}

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

	if !bytes.Equal(a.toBytes(), aBytes) {
		t.Error("Got ", a.toBytes(), " wanted ", aBytes)
	}
}

func TestGenPublicKey(t *testing.T) {
	pubKey := GenPublicKey(testdata.Seed, testdata.PubSeed, Address{})

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong key")
	}
}

func TestSign(t *testing.T) {
	signature := Sign(testdata.Message, testdata.Seed, testdata.PubSeed, Address{})

	if !bytes.Equal(signature, testdata.Signature) {
		t.Error("Wrong signature")
	}
}

func TestPkFromSig(t *testing.T) {
	pubKey := PkFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, Address{})

	if !bytes.Equal(pubKey, testdata.PubKey) {
		t.Error("Wrong public key")
	}
}

func TestVerify(t *testing.T) {
	if !Verify(testdata.PubKey, testdata.Signature, testdata.Message, testdata.PubSeed, Address{}) {
		t.Error("Wrong public key")
	}
}

func BenchmarkGenPublicKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GenPublicKey(testdata.Seed, testdata.PubSeed, Address{})
	}
}

func BenchmarkSign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Sign(testdata.Message, testdata.Seed, testdata.PubSeed, Address{})
	}
}

func BenchmarkPkFromSig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = PkFromSig(testdata.Signature, testdata.Message, testdata.PubSeed, Address{})
	}
}