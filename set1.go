package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBase64(h string) string {
	ret, _ := hex.DecodeString(h)
	return base64.StdEncoding.EncodeToString(ret)
}

func FixedXOR(a, b string) string {
	ba, _ := hex.DecodeString(a)
	bb, _ := hex.DecodeString(b)

	if len(ba) != len(bb) {
		panic("a and b have different sizes")
	}

	ret := make([]byte, len(ba))
	for i := range ret {
		ret[i] = ba[i] ^ bb[i]
	}

	return hex.EncodeToString(ret)
}

func score(in []byte) (s uint) {
	for _, c := range in {
		switch {
		case (c >= '0' && c <= '9'):
			s += 3
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			s += 5
		case c >= ' ' && c <= '~':
			s++
		}
	}

	return
}

func BreakSingleByteXORCipher(in string) string {
	var ret []byte
	key := make([]byte, len(in)/2)
	for c := 0x00; c <= 0xff; c++ {
		for i := range key {
			key[i] = byte(c)
		}

		p, _ := hex.DecodeString(FixedXOR(in, hex.EncodeToString(key)))

		if score(p) > score(ret) {
			ret = p
		}
	}

	return string(ret)
}
