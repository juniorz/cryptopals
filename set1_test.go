package cryptopals_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/juniorz/cryptopals"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type Set1Suite struct{}

var _ = Suite(&Set1Suite{})

func (*Set1Suite) TestHexEncodingScanner(c *C) {
	in := []byte(`0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032
334b041de124f73c18011a50e608097ac308ecee501337ec3e100854201d`)
	s := cryptopals.NewHexEncodingScanner(bytes.NewBuffer(in))

	c.Assert(true, Equals, s.Scan())
	c.Assert(s.Bytes(), DeepEquals, []byte{
		0xe, 0x36, 0x47, 0xe8, 0x59, 0x2d, 0x35, 0x51, 0x4a, 0x8,
		0x12, 0x43, 0x58, 0x25, 0x36, 0xed, 0x3d, 0xe6, 0x73, 0x40,
		0x59, 0x0, 0x1e, 0x3f, 0x53, 0x5c, 0xe6, 0x27, 0x10, 0x32,
	})

	c.Assert(true, Equals, s.Scan())
	c.Assert(s.Bytes(), DeepEquals, []byte{
		0x33, 0x4b, 0x4, 0x1d, 0xe1, 0x24, 0xf7, 0x3c, 0x18, 0x1,
		0x1a, 0x50, 0xe6, 0x8, 0x9, 0x7a, 0xc3, 0x8, 0xec, 0xee,
		0x50, 0x13, 0x37, 0xec, 0x3e, 0x10, 0x8, 0x54, 0x20, 0x1d,
	})

	c.Assert(s.Scan(), Equals, false)
	c.Assert(s.Err(), Equals, nil)
}

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
	plain := cryptopals.BreakSingleByteXORCipher(cipher)
	exp := []byte("Cooking MC's like a pound of bacon")
	c.Assert(plain, DeepEquals, exp)
}

func (*Set1Suite) TestDetectSingleByteXOR(c *C) {
	filename := "data/4.txt"
	f, _ := os.Open(filename)
	defer f.Close()

	exp := []byte("Now that the party is jumping\n")
	detected := cryptopals.DetectSingleByteXOR(f)

	c.Assert(detected, DeepEquals, exp)
}

func (*Set1Suite) TestRepeatingKeyXOR(c *C) {
	key := []byte("ICE")
	plain := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	exp := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
		"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	cipher := cryptopals.RepeatingKeyXOR(key, plain)
	c.Assert(cipher, Equals, exp)
}
