package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io"
)

// HexToBase64 solves challenge 1
// maybe I cheated
func HexToBase64(h string) string {
	ret, _ := hex.DecodeString(h)
	return base64.StdEncoding.EncodeToString(ret)
}

// FixedXOR solves challenge 2
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

// BreakSingleByteXORCipher solves challenge 3
func BreakSingleByteXORCipher(in string) (string, uint) {
	var candidate singleByteXORCandidate
	key := make([]byte, len(in)/2)
	for c := 0x00; c <= 0xff; c++ {
		for i := range key {
			key[i] = byte(c)
		}

		p, _ := hex.DecodeString(FixedXOR(in, hex.EncodeToString(key)))

		if s := score(p); s > candidate.score {
			candidate = singleByteXORCandidate{p, s}
		}
	}

	return string(candidate.key), candidate.score
}

type singleByteXORCandidate struct {
	key   []byte
	score uint
}

func score(in []byte) (s uint) {
	for _, c := range in {
		switch c {
		case 'E', 'T', 'A', 'O', 'I', 'N', ' ', 'S', 'H', 'R', 'D', 'L', 'U':
		case 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u':
			s += 7
		default:
			switch {
			case (c >= '0' && c <= '9'):
				s += 3
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
				s += 5
			case c >= ' ' && c <= '~':
				s++
			}
		}
	}

	return
}

// DetectSingleByteXOR solves challenge 4
func DetectSingleByteXOR(r io.Reader) string {
	var bestScore uint
	var ret string

	s := bufio.NewScanner(r)

	for s.Scan() {
		k, s := BreakSingleByteXORCipher(s.Text())

		if s > bestScore {
			bestScore = s
			ret = k
		}
	}

	return ret
}
