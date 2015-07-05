package cryptopals_test

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/juniorz/cryptopals"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type Set1Suite struct{}

var _ = Suite(&Set1Suite{})

func (*Set1Suite) TestConvertHexToBase64(c *C) {
	src := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	exp := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	c.Assert(exp, Equals, cryptopals.HexToBase64(src))
}

func decodeHex(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}

	return out
}

func (*Set1Suite) TestFixedXOR(c *C) {
	a := decodeHex("1c0111001f010100061a024b53535009181c")
	b := decodeHex("686974207468652062756c6c277320657965")
	exp := decodeHex("746865206b696420646f6e277420706c6179")

	c.Assert(exp, DeepEquals, cryptopals.FixedXOR(a, b))
}

func (*Set1Suite) TestBreakSingleByteXOR(c *C) {
	cipher := decodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	plain, _ := cryptopals.BreakSingleByteXORCipher(cipher)
	exp := []byte("Cooking MC's like a pound of bacon")
	c.Assert(plain, DeepEquals, exp)
}

func (*Set1Suite) TestDetectSingleByteXOR(c *C) {
	filename := "data/4.txt"
	f, _ := os.Open(filename)
	defer f.Close()

	exp := "Now that the party is jumping\n"
	detected := cryptopals.DetectSingleByteXOR(f)

	c.Assert(detected, Equals, exp)
}