package cryptopals_test

import (
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

func (*Set1Suite) TestFixedXOR(c *C) {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"
	exp := "746865206b696420646f6e277420706c6179"

	c.Assert(exp, Equals, cryptopals.FixedXOR(a, b))
}

func (*Set1Suite) TestBreakSingleByteXOR(c *C) {
	plain := cryptopals.BreakSingleByteXORCipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	exp := "Cooking MC's like a pound of bacon"
	c.Assert(plain, Equals, exp)
}